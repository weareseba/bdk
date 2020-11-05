// Magical Bitcoin Library
// Written in 2020 by
//     Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020 Magical Bitcoin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::str::FromStr;

use bitcoin::blockdata::{
    opcodes,
    script::{Builder, Script},
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};
use bitcoin::consensus::encode::Decodable;
use bitcoin::hash_types::{PubkeyHash, Txid};
use bitcoin::util::psbt::{self, Input, PartiallySignedTransaction as PSBT};
use bitcoin::util::address::Payload;

use bitcoin_hashes::{Hash, hash160, sha256d};

#[allow(unused_imports)]
use log::{debug, error, info, trace};

use super::tx_builder::TxBuilder;

use crate::blockchain::BlockchainMarker;
use crate::database::{BatchDatabase, DatabaseUtils};
use crate::error::Error;
use crate::wallet::Wallet;

/// The API for proof of reserves
/// https://github.com/bitcoin/bips/blob/master/bip-0127.mediawiki
/// https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki
pub trait ProofOfReserves {
    /// Create a proof for all spendable UTXOs in a wallet
    fn create_proof(&self, message: &str) -> Result<PSBT, Error> {
        self.do_create_proof(message)
    }
    /// Make sure this is a proof, and not a spendable transaction.
    /// Returns the spendable amount of the proof.
    fn verify_proof(&self, psbt: &PSBT, message: &str) -> Result<u64, Error> {
        return self.do_verify_proof(psbt, message)
    }

    fn do_create_proof(&self, message: &str) -> Result<PSBT, Error>;
    fn do_verify_proof(&self, psbt: &PSBT, message: &str) -> Result<u64, Error>;
    // ToDo: how can we remove this helper function from the trait definition, but keep in the implementation?
    fn get_spendable_value_from_input(&self, pinp: &psbt::Input,) -> Result<u64, Error>;
}

impl<B, D> ProofOfReserves for Wallet<B, D>
where
    B: BlockchainMarker,
    D: BatchDatabase,
{
    fn do_create_proof(&self, message: &str) -> Result<PSBT, Error> {
        let message = "Proof-of-Reserves: ".to_string() + message;
        let message = sha256d::Hash::hash(message.as_bytes());
        let challenge_txin = TxIn {
            previous_output: OutPoint::new(Txid::from_hash(message), 0),
            sequence: 0xFFFFFFFF,
		    script_sig: Builder::new().into_script(),
            witness: Vec::new(),
        };
        let challenge_psbt_inp = Input {
			witness_utxo: Some(TxOut {
				value: 0,
				script_pubkey: Builder::new().push_opcode(opcodes::OP_TRUE).into_script(),
			}),
			witness_script: Some(Builder::new().into_script()),
			final_script_sig: Some(Builder::new().into_script()),
			..Default::default()
		};

        let mut tx_inputs = Vec::new();
        let mut psbt_inputs = Vec::new();
        tx_inputs.push(challenge_txin);
        psbt_inputs.push(challenge_psbt_inp);

        let utxos = self.database.borrow().iter_utxos()?;
        let mut sum_amount = 0;
        for utxo in utxos {
            let proof_txin = TxIn{
                previous_output: utxo.outpoint,
                sequence: 0xFFFFFFFF,
                script_sig: Builder::new().into_script(),
                witness: Vec::new(),
            };
            let proof_psbt_inp = Input{
                // ToDo: unsure about the next few lines
                witness_utxo: Some(TxOut {
                    value: 0,
                    script_pubkey: Builder::new().push_opcode(opcodes::OP_TRUE).into_script(),
                }),
                witness_script: Some(Builder::new().into_script()),
                final_script_sig: Some(Builder::new().into_script()),
                ..Default::default()
            };
            tx_inputs.push(proof_txin);
            psbt_inputs.push(proof_psbt_inp);
            sum_amount += utxo.txout.value;
        }

        let pkh = PubkeyHash::from_hash(hash160::Hash::hash(&[0]));
		let out_script_unspendable = bitcoin::Address {
			payload: Payload::PubkeyHash(pkh),
			network: self.network,
		}.script_pubkey();

		// Construct the tx and psbt tx.
		let tx = Transaction {
			version: 1,
			lock_time: 0xffffffff, // Max time in the future. 2106-02-07 06:28:15
			input: tx_inputs,
			output: vec![TxOut {
				value: sum_amount as u64,
				script_pubkey: out_script_unspendable,
			}],
		};
		let mut psbt = PSBT::from_unsigned_tx(tx)
			.expect("error constructing PSBT from unsigned tx");
        psbt.inputs = psbt_inputs;
        // We can leave the one psbt output empty.

        Ok(psbt)
    }

    fn do_verify_proof(&self, psbt: &PSBT, message: &str) -> Result<u64, Error> {
        let tx = psbt.clone().extract_tx();

        // verify the challenge txin
        let message = "Proof-of-Reserves: ".to_string() + message;
        let message = sha256d::Hash::hash(message.as_bytes());
        let fake_txid = Txid::from_hash(message);
        assert_eq!(tx.input[0].previous_output.txid, fake_txid);

        // verify the proof UTXOs
        let mut sum = 0;
        for inp in psbt.inputs.iter().skip(1) {
            sum += self.get_spendable_value_from_input(inp)?;
            // ToDo: verify the signature
        }

        // verify the unspendable output
        assert_eq!(tx.output.len(), 1);
        let pkh = PubkeyHash::from_hash(hash160::Hash::hash(&[0]));
		let out_script_unspendable = bitcoin::Address {
			payload: Payload::PubkeyHash(pkh),
			network: self.network,
		}.script_pubkey();
        assert_eq!(tx.output[0].script_pubkey, out_script_unspendable);

        Ok(sum)
    }

    /// Calculate the spendable value from an input
    // ToDo: some refactoring needed
    fn get_spendable_value_from_input(&self,
        pinp: &psbt::Input,
    ) -> Result<u64, Error> {
        if pinp.witness_utxo.is_some() {
            return Ok(pinp.witness_utxo.as_ref().unwrap().value);
        };
        if pinp.non_witness_utxo.is_some() {
            let mut err1: std::result::Result<(), Error> = Ok(());
            let mut err2: std::result::Result<(), Error> = Ok(());
            let value = pinp
                .non_witness_utxo
                .as_ref()
                .unwrap()
                .output
                .iter()
                .map(|txout| {
                    match bitcoin::Address::from_script(&txout.script_pubkey, self.network) {
                        Some(addr) => Ok((addr, txout.value)),
                        None => Err(Error::Generic("no address".to_string()))
                    }
                })
                .scan(&mut err1, |err1, res| match res {
                    Ok(o) => Some(o),
                    Err(e) => {
                        **err1 = Err(e);
                        None
                    }
                })
                .map(|(prev_addr, value)| { 
                    let is_mine = self.database.borrow().is_mine(&prev_addr.script_pubkey())?;
                    Ok((is_mine, value))
                })
                .scan(&mut err2, |err2, res| match res {
                    Ok(o) => Some(o),
                    Err(e) => {
                        **err2 = Err(e);
                        None
                    }
                })
                .filter(|(is_mine, value)| *is_mine)
                .fold(0, |acc, (_prev_addr, value)| acc + value);
            err1?;
            err2?;
            return Ok(value);
        };

        Ok(0)
    }
}


#[cfg(test)]
mod test {
    use bitcoin::{Network, Txid};
    use rstest::rstest;

    use super::*;
    use crate::database::{memory::MemoryDatabase, BatchOperations};
    use crate::types::TransactionDetails;
    use crate::wallet::OfflineWallet;

    fn get_test_db() -> MemoryDatabase {
        let mut db = MemoryDatabase::new();
        db.set_tx(&TransactionDetails {
            transaction: None,
            txid: Txid::from_str(
                "4ddff1fa33af17f377f62b72357b43107c19110a8009b36fb832af505efed98a",
            )
            .unwrap(),
            timestamp: 12345678,
            received: 100_000,
            sent: 0,
            fees: 500,
            height: Some(5000),
        })
        .unwrap();

        db
    }

    pub(crate) fn get_funded_wallet(
        descriptor: &str,
        network: Network,
    ) -> (
        OfflineWallet<MemoryDatabase>,
        (String, Option<String>),
        bitcoin::Txid,
    ) {
        let descriptors = testutils!(@descriptors (descriptor));
        let wallet: OfflineWallet<_> = Wallet::new_offline(
            &descriptors.0,
            None,
            network,
            MemoryDatabase::new(),
        )
        .unwrap();

        let txid = wallet.database.borrow_mut().received_tx(
            testutils! {
                @tx ( (@external descriptors, 0) => 50_000 ) (@confirmations 1)
            },
            Some(100),
        );

        (wallet, descriptors, txid)
    }

    pub(crate) fn get_test_xprv() -> &'static str {
        "wpkh(xprv9s21ZrQH143K4CTb63EaMxja1YiTnSEWKMbn23uoEnAzxjdUJRQkazCAtzxGm4LSoTSVTptoV9RbchnKPW9HxKtZumdyxyikZFDLhogJ5Uj/44'/0'/0'/0/*)"
    }

    pub(crate) fn get_test_wpkh() -> &'static str {
        "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)"
    }

    pub(crate) fn get_test_single_sig_csv() -> &'static str {
        // and(pk(Alice),older(6))
        "wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))"
    }

    pub(crate) fn get_test_single_sig_cltv() -> &'static str {
        // and(pk(Alice),after(100000))
        "wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),after(100000)))"
    }


    #[rstest(descriptor,
        case(get_test_xprv()),
        case(get_test_wpkh()),
        case(get_test_single_sig_csv()),
        case(get_test_single_sig_cltv())
    )]
    fn test_proof(descriptor: &'static str) {
        let (wallet, _, _) = get_funded_wallet(descriptor, Network::Bitcoin);

        let message = "This belongs to me because I am poor.";
        let psbt = wallet.create_proof(&message).unwrap();

        let (signed_psbt, _finalized) = wallet.sign(psbt, None).unwrap();

        let spendable = wallet.verify_proof(&signed_psbt, &message).unwrap();
        assert_eq!(spendable, 0);
    }


/*
    #[test]
    fn test_proof_bip44() {
        let descriptor = "wpkh(xprv9s21ZrQH143K4CTb63EaMxja1YiTnSEWKMbn23uoEnAzxjdUJRQkazCAtzxGm4LSoTSVTptoV9RbchnKPW9HxKtZumdyxyikZFDLhogJ5Uj/44'/0'/0'/0/*)";
        let change_descriptor = "wpkh(xprv9s21ZrQH143K4CTb63EaMxja1YiTnSEWKMbn23uoEnAzxjdUJRQkazCAtzxGm4LSoTSVTptoV9RbchnKPW9HxKtZumdyxyikZFDLhogJ5Uj/44'/0'/0'/1/*)";

        let wallet: OfflineWallet<_> = Wallet::new_offline(
            descriptor,
            Some(change_descriptor),
            Network::Bitcoin,
            get_test_db(),
        )
        .unwrap();

        let message = "Everything belongs to me because I am poor.";
        let psbt = wallet.create_proof(&message).unwrap();
        ensure_is_proof(&psbt, &message).unwrap();
    }

    #[test]
    fn test_proof_multi() {
        let descriptor = "wsh(multi(2,\
                                [73756c7f/48'/0'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*,\
                                [f9f62194/48'/0'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/0/*,\
                                [c98b1535/48'/0'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/0/*\
                          ))";
        let change_descriptor = "wsh(multi(2,\
                                       [73756c7f/48'/0'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/1/*,\
                                       [f9f62194/48'/0'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/1/*,\
                                       [c98b1535/48'/0'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/1/*\
                                 ))";

        let wallet: OfflineWallet<_> = Wallet::new_offline(
            descriptor,
            Some(change_descriptor),
            Network::Testnet,
            get_test_db(),
        )
        .unwrap();

        let message = "All these BTC are mine.";
        let psbt = wallet.create_proof(&message).unwrap();
        ensure_is_proof(&psbt, &message).unwrap();
    }
*/*/*/*/*/*/*/*/*/
}
