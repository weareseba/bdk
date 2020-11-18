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

use bitcoin::blockdata::{
    opcodes,
    script::Builder,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};
use bitcoin::hash_types::{PubkeyHash, Txid};
use bitcoin::util::address::Payload;
use bitcoin::util::psbt::{self, Input, PartiallySignedTransaction as PSBT};

use bitcoin_hashes::{hash160, sha256d, Hash};

#[allow(unused_imports)]
use log::{debug, error, info, trace};

use crate::blockchain::BlockchainMarker;
use crate::database::BatchDatabase;
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
        self.do_verify_proof(psbt, message)
    }

    fn do_create_proof(&self, message: &str) -> Result<PSBT, Error>;
    fn do_verify_proof(&self, psbt: &PSBT, message: &str) -> Result<u64, Error>;
    // ToDo: how can we remove this helper function from the trait definition, but keep in the implementation?
    fn get_spendable_value_from_input(&self, pinp: &psbt::Input) -> Result<u64, Error>;
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

        let utxos = self.list_unspent()?;
        let mut sum_amount = 0;
        for utxo in utxos {
            let proof_txin = TxIn {
                previous_output: utxo.outpoint,
                sequence: 0xFFFFFFFF,
                script_sig: Builder::new().into_script(),
                witness: Vec::new(),
            };
            let proof_psbt_inp = Input {
                // ToDo: unsure about the next few lines
                witness_utxo: Some(TxOut {
                    value: utxo.txout.value,
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
        }
        .script_pubkey();

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
        let mut psbt =
            PSBT::from_unsigned_tx(tx).expect("error constructing PSBT from unsigned tx");
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
        let first_txid = tx.input[0].previous_output.txid;
        if first_txid != fake_txid {
            return Err(Error::ProofOfReservesInvalid);
        }

        // verify the proof UTXOs
        let _utxos = self.list_unspent()?;
/*
        let _client = match self.client() {
            Some(cli) => cli,
            None => return Err(Error::CannotVerifyProof),
        };
*/
        let mut sum = 0;
        for inp in psbt.inputs.iter().skip(1) {
            sum += self.get_spendable_value_from_input(inp)?;
        }

        // ToDo: verify that the proof inputs were spendable at the block height of the proof

        // ToDo: verify the signatures

        // verify the unspendable output
        assert_eq!(tx.output.len(), 1);
        let pkh = PubkeyHash::from_hash(hash160::Hash::hash(&[0]));
        let out_script_unspendable = bitcoin::Address {
            payload: Payload::PubkeyHash(pkh),
            network: self.network,
        }
        .script_pubkey();
        if tx.output[0].script_pubkey != out_script_unspendable {
            return Err(Error::ProofOfReservesInvalid);
        }

        Ok(sum)
    }

    /// Calculate the spendable value from an input
    fn get_spendable_value_from_input(&self, pinp: &psbt::Input) -> Result<u64, Error> {
        if pinp.witness_utxo.is_none() {
            return Err(Error::ProofOfReservesInvalid);
        };
        Ok(pinp.witness_utxo.as_ref().unwrap().value)
    }
}

#[cfg(test)]
mod test {
    use bitcoin::{secp256k1::Secp256k1, Network, util::key::{PrivateKey, PublicKey}};
    use bitcoin_ypub::util::bip32::{DefaultResolver, DerivationPath, ExtendedPrivKey};
    use rstest::rstest;

    use super::*;
    use crate::blockchain::{noop_progress, ElectrumBlockchain};
    use crate::database::memory::MemoryDatabase;
    use crate::electrum_client::Client;
    use crate::wallet::OfflineWallet;
    
    use std::str::FromStr;

    pub(crate) fn get_funded_wallet(
        descriptor: &str,
        network: Network,
    ) -> (
        OfflineWallet<MemoryDatabase>,
        (String, Option<String>),
        bitcoin::Txid,
    ) {
        let descriptors = testutils!(@descriptors (descriptor));
        let wallet: OfflineWallet<_> =
            Wallet::new_offline(&descriptors.0, None, network, MemoryDatabase::new()).unwrap();

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

    #[rstest(
        descriptor,
        case(get_test_xprv()),
        case(get_test_wpkh()),
        case(get_test_single_sig_csv()),
        case(get_test_single_sig_cltv())
    )]
    fn test_proof(descriptor: &'static str) {
        let (wallet, _, _) = get_funded_wallet(descriptor, Network::Bitcoin);
        let balance = wallet.get_balance().unwrap();

        let message = "This belongs to me.";
        let psbt = wallet.create_proof(&message).unwrap();

        let (signed_psbt, _finalized) = wallet.sign(psbt, None).unwrap();

        let spendable = wallet.verify_proof(&signed_psbt, &message).unwrap();
        assert_eq!(spendable, balance);
    }

    fn get_private_key(xprv: &str, derivation: &DerivationPath) -> PrivateKey {
        let xprv = ExtendedPrivKey::<DefaultResolver>::from_str(xprv).unwrap();
        let secp = Secp256k1::new();
        let private_key = xprv.derive_priv(&secp, &derivation).unwrap().private_key;
        // ToDo: the following is only because we use different versions of the bitcoin library. Once this is resolved, remove this conversion.
        let private_key = PrivateKey::from_wif(&private_key.to_wif()).unwrap();
        private_key
    }

    fn get_public_key(xprv: &str, derivation: &DerivationPath) -> PublicKey {
        let private_key = get_private_key(xprv, derivation);
        let secp = Secp256k1::new();
        let public_key = private_key.public_key(&secp);
        public_key
    }

    fn construct_multisig_wallet(signer: &PrivateKey, pubkeys: &Vec<PublicKey>) -> Wallet<ElectrumBlockchain, MemoryDatabase> {
        let secp = Secp256k1::new();
        let pub_derived = signer.public_key(&secp);

        let desc =
            pubkeys
            .iter()
            .enumerate()
            .fold("sh(wsh(multi(2,".to_string(), |acc, (i, pubkey)| {
                let mut desc = acc;
                if i != 0 {
                    desc += ",";
                }
                if *pubkey == pub_derived {
                    desc += &signer.to_wif();
                } else {
                    desc += &pubkey.to_string();
                }
                desc
            })
            + ")))";

        let client = Client::new("ssl://electrum.blockstream.info:60002", None).unwrap();
        let wallet = Wallet::new(
            &desc,
            None,
            Network::Testnet,
            MemoryDatabase::default(),
            ElectrumBlockchain::from(client),
        ).unwrap();

        wallet.sync(noop_progress(), None).unwrap();

        wallet
    }

    #[test]
    fn test_proof_multisig() {
        let signer1 = "tprv8ZgxMBicQKsPdE3fMYvuvfo71bRG48RcUvSRpQ8ZTYPbRDZYGpUDzFXuhnv65yLDyTvBY47gGYQ8FjKurEWz4puybNUT3YDZKDwFW5F6Sqj";
        let signer2 = "tprv8ZgxMBicQKsPes5uvZUX5fZKJyrSZCYW8oZmdS2mCTxWkccQv5YWA53eik4aAVEDqgqQCzgscD7RwynCmFQtFLkz22Ro9gSotJ92n36CnLY";
        let signer3 = "tprv8ZgxMBicQKsPeV7DR58om537hMTHkj1W4X6Ewp6D8gxS1oFaNSuh72YpYqoCNyMTvRrAEn6MrUQb43wPGxpYUQ3Jo13D7jAXFz9NgHM1tUC";
        let derivation = DerivationPath::from_str("m/0/0").unwrap();
        let mut pubkeys = vec![get_public_key(signer1, &derivation), get_public_key(signer2, &derivation), get_public_key(signer3, &derivation)];
        pubkeys.sort_by_key(|item| item.to_string());
        let wallet1 = construct_multisig_wallet(&get_private_key(signer1, &derivation), &pubkeys);
        let wallet2 = construct_multisig_wallet(&get_private_key(signer2, &derivation), &pubkeys);
        let wallet3 = construct_multisig_wallet(&get_private_key(signer3, &derivation), &pubkeys);
        let address = wallet1.get_new_address().unwrap();
        assert_eq!(address.to_string(), "2NDTiUegP4NwKMnxXm6KdCL1B1WHamhZHC1");
        let balance = wallet1.get_balance().unwrap();
        assert_eq!(balance, 410000);
        
        let message = "All my precious coins";
        let psbt = wallet1.create_proof(message).unwrap();

        let (psbt, _finalized) = wallet1.sign(psbt, None).unwrap();
        let (psbt, _finalized) = wallet2.sign(psbt, None).unwrap();
        let (psbt, _finalized) = wallet3.sign(psbt, None).unwrap();

        let spendable = wallet1.verify_proof(&psbt, &message).unwrap();
        assert_eq!(spendable, balance);
    }
}
