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

use bitcoin::{
    blockdata::{
        opcodes,
        script::Builder,
        transaction::{OutPoint, Transaction, TxIn, TxOut},
    },
    consensus::encode::serialize,
    hash_types::{PubkeyHash, Txid},
    util::{
        address::Payload,
        psbt::{self, Input, PartiallySignedTransaction as PSBT},
    },
};
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
        let challenge_txin = challenge_txin(message);
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

        if tx.output.len() != 1 {
            return Err(Error::ProofOfReservesInvalid(format!(
                "Wrong number of outputs: {}",
                tx.output.len()
            )));
        }
        if tx.input.len() <= 1 {
            return Err(Error::ProofOfReservesInvalid(format!(
                "Wrong number of inputs: {}",
                tx.input.len()
            )));
        }

        // verify the challenge txin
        let challenge_txin = challenge_txin(message);
        if tx.input[0].previous_output != challenge_txin.previous_output {
            return Err(Error::ProofOfReservesInvalid(
                "Challenge txin mismatch".to_string(),
            ));
        }

        // verify the proof UTXOs are still spendable
        // ToDo: verify that the proof inputs were spendable at the block height of the proof
        let utxos = self.list_unspent()?;
        if let Some(inp) = tx
            .input
            .iter()
            .skip(1)
            .find(|i| utxos.iter().find(|u| u.outpoint == i.previous_output) == None)
        {
            return Err(Error::ProofOfReservesInvalid(format!(
                "Found an input that is not spendable: {:?}",
                inp
            )));
        }

        // verify that the inputs are signed, except the challenge
        if let Some(inp) = tx
            .input
            .iter()
            .skip(1)
            .find(|i| i.script_sig == Builder::new().into_script())
        {
            return Err(Error::ProofOfReservesInvalid(format!(
                "Found an input that is not signed: {:?}",
                inp
            )));
        }

        // Verify other inputs against prevouts and calculate the amount.
        // ToDo: make sure this is enough to verify the signatures
        let serialized_tx = serialize(&tx);
        for (idx, utxo) in utxos.into_iter().enumerate() {
            // Verify the script execution of the input.
            if let Err(err) = bitcoinconsensus::verify(
                utxo.txout.script_pubkey.to_bytes().as_slice(),
                utxo.txout.value,
                &serialized_tx,
                idx + 1, // skipped the challenge input
            ) {
                return Err(Error::ProofOfReservesInvalid(format!("{:?}", err)));
            }
        }

        // calculate the spendable amount of the proof
        let sum = psbt.inputs.iter().fold(0, |acc, inp| {
            acc + self.get_spendable_value_from_input(inp).unwrap_or(0)
        });

        // verify the unspendable output
        let pkh = PubkeyHash::from_hash(hash160::Hash::hash(&[0]));
        let out_script_unspendable = bitcoin::Address {
            payload: Payload::PubkeyHash(pkh),
            network: self.network,
        }
        .script_pubkey();
        if tx.output[0].script_pubkey != out_script_unspendable {
            return Err(Error::ProofOfReservesInvalid("Invalid output".to_string()));
        }

        Ok(sum)
    }

    /// Calculate the spendable value from an input
    fn get_spendable_value_from_input(&self, pinp: &psbt::Input) -> Result<u64, Error> {
        if pinp.witness_utxo.is_none() {
            return Err(Error::ProofOfReservesInvalid(
                "Failed to deterrmine the amount of an input".to_string(),
            ));
        };
        Ok(pinp.witness_utxo.as_ref().unwrap().value)
    }
}

/// Construct a challenge input with the message
fn challenge_txin(message: &str) -> TxIn {
    let message = "Proof-of-Reserves: ".to_string() + message;
    let message = sha256d::Hash::hash(message.as_bytes());
    TxIn {
        previous_output: OutPoint::new(Txid::from_hash(message), 0),
        sequence: 0xFFFFFFFF,
        script_sig: Builder::new().into_script(),
        witness: Vec::new(),
    }
}

#[cfg(test)]
mod test {
    use bitcoin::{
        consensus::Encodable,
        secp256k1::Secp256k1,
        util::key::{PrivateKey, PublicKey},
        Network,
    };
    use rstest::rstest;
    use std::{
        fs::{self, File},
        io::Write,
    };

    use super::*;
    use crate::blockchain::{noop_progress, ElectrumBlockchain};
    use crate::database::memory::MemoryDatabase;
    use crate::electrum_client::Client;
    use crate::wallet::OfflineWallet;

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

    #[rstest(
        descriptor,
//        case("wpkh(xprv9s21ZrQH143K4CTb63EaMxja1YiTnSEWKMbn23uoEnAzxjdUJRQkazCAtzxGm4LSoTSVTptoV9RbchnKPW9HxKtZumdyxyikZFDLhogJ5Uj/44'/0'/0'/0/*)"),
        case("wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)"),
        case("wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))"),     // and(pk(Alice),older(6))
        case("wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),after(100000)))") // and(pk(Alice),after(100000))
    )]
    fn test_proof(descriptor: &'static str) -> Result<(), Error> {
        let (wallet, _, _) = get_funded_wallet(descriptor, Network::Bitcoin);
        let balance = wallet.get_balance()?;

        let message = "This belongs to me.";
        let psbt = wallet.create_proof(&message)?;
        let num_inp = psbt.inputs.len();
        assert!(
            num_inp > 1,
            "num_inp is {} but should be more than 1",
            num_inp
        );

        let (signed_psbt, _finalized) = wallet.sign(psbt, None)?;
        let num_sigs = signed_psbt
            .inputs
            .iter()
            .fold(0, |acc, i| acc + i.partial_sigs.len());
        assert_eq!(num_sigs, (num_inp - 0) * 1);

        let spendable = wallet.verify_proof(&signed_psbt, &message)?;
        assert_eq!(spendable, balance);

        Ok(())
    }

    enum MultisigType {
        Wsh,
        ShWsh,
        P2sh,
    }

    fn construct_multisig_wallet(
        signer: &PrivateKey,
        pubkeys: &Vec<PublicKey>,
        script_type: &MultisigType,
    ) -> Result<Wallet<ElectrumBlockchain, MemoryDatabase>, Error> {
        let secp = Secp256k1::new();
        let pub_derived = signer.public_key(&secp);

        let (prefix, postfix) = match script_type {
            MultisigType::Wsh => ("wsh(", ")"),
            MultisigType::ShWsh => ("sh(wsh(", "))"),
            MultisigType::P2sh => ("sh(", ")"),
        };
        let prefix = prefix.to_string() + "multi(2,";
        let postfix = postfix.to_string() + ")";
        let desc = pubkeys.iter().enumerate().fold(prefix, |acc, (i, pubkey)| {
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
        }) + &postfix;

        let client = Client::new("ssl://electrum.blockstream.info:60002", None)?;
        let wallet = Wallet::new(
            &desc,
            None,
            Network::Testnet,
            MemoryDatabase::default(),
            ElectrumBlockchain::from(client),
        )?;

        wallet.sync(noop_progress(), None)?;

        Ok(wallet)
    }

    #[rstest(
        script_type,
        expected_address,
        case(
            MultisigType::Wsh,
            "tb1qnmhmxkaqqz4lrruhew5mk6zqr0ezstn3stj6c3r2my6hgkescm0sg3qc0r"
        ),
        case(MultisigType::ShWsh, "2NDTiUegP4NwKMnxXm6KdCL1B1WHamhZHC1"),
        case(MultisigType::P2sh, "2N7yrzYXgQzNQQuHNTjcP3iwpzFVsqe6non")
    )]
    fn test_proof_multisig(
        script_type: MultisigType,
        expected_address: &'static str,
    ) -> Result<(), Error> {
        let signer1 =
            PrivateKey::from_wif("cQCi6JdidZN5HeiHhjE7zZAJ1XJrZbj6MmpVPx8Ri3Kc8UjPgfbn").unwrap();
        let signer2 =
            PrivateKey::from_wif("cTTgG6x13nQjAeECaCaDrjrUdcjReZBGspcmNavsnSRyXq7zXT7r").unwrap();
        let signer3 =
            PrivateKey::from_wif("cUPkz3JBZinD1RRU7ngmx8cssqJ4KgBvboq1QZcGfyjqm8L6etRH").unwrap();
        let secp = Secp256k1::new();
        let mut pubkeys = vec![
            signer1.public_key(&secp),
            signer2.public_key(&secp),
            signer3.public_key(&secp),
        ];
        pubkeys.sort_by_key(|item| item.to_string());

        let wallet1 = construct_multisig_wallet(&signer1, &pubkeys, &script_type)?;
        let wallet2 = construct_multisig_wallet(&signer2, &pubkeys, &script_type)?;
        let wallet3 = construct_multisig_wallet(&signer3, &pubkeys, &script_type)?;
        assert_eq!(wallet1.get_new_address()?.to_string(), expected_address);
        assert_eq!(wallet2.get_new_address()?.to_string(), expected_address);
        assert_eq!(wallet3.get_new_address()?.to_string(), expected_address);
        let balance = wallet1.get_balance()?;
        assert_eq!(balance, 410000);

        let message = "All my precious coins";
        let psbt = wallet1.create_proof(message)?;
        let num_inp = psbt.inputs.len();
        assert!(
            num_inp > 1,
            "num_inp is {} but should be more than 1",
            num_inp
        );

        let count_signatures = |psbt: &PSBT| {
            psbt.inputs
                .iter()
                .fold(0, |acc, i| acc + i.partial_sigs.len())
        };

        let (psbt, _finalized) = wallet1.sign(psbt, None)?;
        assert_eq!(count_signatures(&psbt), (num_inp - 0) * 1);

        let (psbt, _finalized) = wallet2.sign(psbt, None)?;
        assert_eq!(count_signatures(&psbt), (num_inp - 0) * 2);

        let (psbt, _finalized) = wallet3.sign(psbt, None)?;
        assert_eq!(count_signatures(&psbt), (num_inp - 0) * 3);

        let (psbt, finalized) = wallet1.finalize_psbt(psbt, None)?;
        assert_eq!(count_signatures(&psbt), (num_inp - 0) * 3);
        if !finalized {
            write_to_temp_file(&psbt);
        }

        let spendable = wallet1.verify_proof(&psbt, &message)?;
        assert_eq!(spendable, balance);

        Ok(())
    }

    fn write_to_temp_file(psbt: &PSBT) {
        let data = encode_tx(psbt).unwrap();
        let filename = "/tmp/psbt";
        fs::remove_file(filename);
        let mut file = File::create(&filename).unwrap();
        file.write_all(&data);
        file.sync_all();
    }

    fn encode_tx(psbt: &PSBT) -> Result<Vec<u8>, Error> {
        let mut encoded = Vec::<u8>::new();
        if psbt.consensus_encode(&mut encoded).is_err() {
            return Err(Error::CannotVerifyProof);
        }
        let tx = base64::encode(&encoded);

        Ok(tx.as_bytes().to_vec())
    }
}
