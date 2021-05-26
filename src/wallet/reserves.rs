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

//! Proof of reserves
//!
//! This module provides the ability to create proofs of reserves.
//! A proof is a valid but unspendable transaction. By signing a transaction
//! that spends some UTXOs we are proofing that we have control over these funds.
//! The implementation is inspired by the following BIPs:
//! https://github.com/bitcoin/bips/blob/master/bip-0127.mediawiki
//! https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki

use bitcoin::{
    blockdata::{
        opcodes,
        script::{Builder, Script},
        transaction::{OutPoint, SigHashType, TxIn, TxOut},
    },
    consensus::encode::serialize,
    hash_types::{PubkeyHash, Txid},
    util::{
        address::Payload,
        psbt::{Input, PartiallySignedTransaction as PSBT},
    },
    Network,
};
use bitcoin_hashes::{hash160, sha256d, Hash};
use bitcoinconsensus;

#[allow(unused_imports)]
use log::{debug, error, info, trace};

use crate::database::BatchDatabase;
use crate::error::Error;
use crate::wallet::Wallet;

/// The API for proof of reserves
pub trait ProofOfReserves {
    /// Create a proof for all spendable UTXOs in a wallet
    fn create_proof(&self, message: &str) -> Result<PSBT, Error> {
        self.do_create_proof(message)
    }
    /// Make sure this is a proof, and not a spendable transaction.
    /// Make sure the proof is valid.
    /// Currently proofs can only be validated against the tip of the chain.
    /// If some of the UTXOs in the proof were spent in the meantime, the proof will fail.
    /// We can currently not validate whether it was valid at a certain block height.
    /// Returns the spendable amount of the proof.
    fn verify_proof(&self, psbt: &PSBT, message: &str) -> Result<u64, Error> {
        self.do_verify_proof(psbt, message)
    }

    /// implementation
    fn do_create_proof(&self, message: &str) -> Result<PSBT, Error>;
    /// implementation
    fn do_verify_proof(&self, psbt: &PSBT, message: &str) -> Result<u64, Error>;
}

impl<B, D> ProofOfReserves for Wallet<B, D>
where
    D: BatchDatabase,
{
    fn do_create_proof(&self, message: &str) -> Result<PSBT, Error> {
        let challenge_txin = challenge_txin(message);
        let challenge_psbt_inp = Input {
            witness_utxo: Some(TxOut {
                value: 0,
                script_pubkey: Builder::new().push_opcode(opcodes::OP_TRUE).into_script(),
            }),
            final_script_sig: Some(Script::default()), // "finalize" the input with an empty scriptSig
            ..Default::default()
        };

        let pkh = PubkeyHash::from_hash(hash160::Hash::hash(&[0]));
        let out_script_unspendable = bitcoin::Address {
            payload: Payload::PubkeyHash(pkh),
            network: self.network,
        }
        .script_pubkey();

        let mut builder = self.build_tx();
        builder
            .drain_wallet()
            .add_foreign_utxo(challenge_txin.previous_output, challenge_psbt_inp, 42)?
            .fee_absolute(0)
            .only_witness_utxo()
            .set_single_recipient(out_script_unspendable);
        let (psbt, _details) = builder.finish().unwrap();

        Ok(psbt)
    }

    fn do_verify_proof(&self, psbt: &PSBT, message: &str) -> Result<u64, Error> {
        // verify the proof UTXOs are still spendable
        let outpoints = self
            .list_unspent()?
            .iter()
            .map(|utxo| utxo.outpoint)
            .collect();

        verify_proof(psbt, message, outpoints, self.network)
    }
}

/// Make sure this is a proof, and not a spendable transaction.
/// Make sure the proof is valid.
/// Currently proofs can only be validated against the tip of the chain.
/// If some of the UTXOs in the proof were spent in the meantime, the proof will fail.
/// We can currently not validate whether it was valid at a certain block height.
/// Returns the spendable amount of the proof.
pub fn verify_proof(
    psbt: &PSBT,
    message: &str,
    outpoints: Vec<OutPoint>,
    network: Network,
) -> Result<u64, Error> {
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
    if let Some(inp) = tx
        .input
        .iter()
        .skip(1)
        .find(|i| outpoints.iter().find(|op| **op == i.previous_output) == None)
    {
        return Err(Error::ProofOfReservesInvalid(format!(
            "Found an input that is not spendable: {:?}",
            inp
        )));
    }

    // verify that the inputs are signed, except the challenge
    if let Some((i, inp)) =
        psbt.inputs.iter().enumerate().skip(1).find(|(_i, inp)| {
            !inp.final_script_sig.is_some() && !inp.final_script_witness.is_some()
        })
    {
        return Err(Error::ProofOfReservesInvalid(format!(
            "Found an input that is not signed at #{} : {:?}",
            i, inp
        )));
    }

    // Make sure each input is either witness or legacy, but not both at the same time.
    if let Some((i, _psbt_in)) =
        psbt.inputs.iter().enumerate().find(|(_i, psbt_in)| {
            psbt_in.witness_utxo.is_some() && psbt_in.non_witness_utxo.is_some()
        })
    {
        return Err(Error::ProofOfReservesInvalid(format!(
            "Witness and legacy input found at input #{}",
            i
        )));
    }

    // Verify the SIGHASH
    if let Some((i, _psbt_in)) = psbt.inputs.iter().enumerate().find(|(_i, psbt_in)| {
        if let Some(sigh_type) = psbt_in.sighash_type {
            match sigh_type {
                SigHashType::All => false,
                SigHashType::None
                | SigHashType::Single
                | SigHashType::AllPlusAnyoneCanPay
                | SigHashType::NonePlusAnyoneCanPay
                | SigHashType::SinglePlusAnyoneCanPay => true,
            }
        } else {
            false
        }
    }) {
        return Err(Error::ProofOfReservesInvalid(format!(
            "unsupported sighash type at input #{}",
            i
        )));
    }

    // Verify other inputs against prevouts and calculate the amount.
    let serialized_tx = serialize(&tx);
    if let Some((i, res)) = psbt
        .inputs
        .iter()
        .zip(tx.input.iter())
        .enumerate()
        .map(|(i, (psbt_in, tx_in))| {
            if let Some(utxo) = &psbt_in.witness_utxo {
                (i, &utxo.script_pubkey, utxo.value)
            } else if let Some(nwtx) = &psbt_in.non_witness_utxo {
                let outp = &nwtx.output[tx_in.previous_output.vout as usize];
                (i, &outp.script_pubkey, outp.value)
            } else {
                panic!("must be either witness or legacy");
            }
        })
        .map(|(i, script, value)| {
            (
                i,
                bitcoinconsensus::verify(script.to_bytes().as_slice(), value, &serialized_tx, i),
            )
        })
        .find(|(_i, res)| res.is_err())
    {
        return Err(Error::ProofOfReservesInvalid(format!(
            "Signature validation error at input #{}: {:?}",
            i,
            res.err().unwrap()
        )));
    }

    // calculate the spendable amount of the proof
    let sum = tx
        .input
        .iter()
        .zip(psbt.inputs.iter())
        .map(|(tx_in, psbt_in)| {
            if let Some(utxo) = &psbt_in.witness_utxo {
                utxo.value
            } else if let Some(nwtx) = &psbt_in.non_witness_utxo {
                nwtx.output[tx_in.previous_output.vout as usize].value
            } else {
                0
            }
        })
        .fold(0, |acc, val| acc + val);

    // verify the unspendable output
    let pkh = PubkeyHash::from_hash(hash160::Hash::hash(&[0]));
    let out_script_unspendable = bitcoin::Address {
        payload: Payload::PubkeyHash(pkh),
        network: network,
    }
    .script_pubkey();
    if tx.output[0].script_pubkey != out_script_unspendable {
        return Err(Error::ProofOfReservesInvalid("Invalid output".to_string()));
    }

    Ok(sum)
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
        consensus::encode::Decodable,
        secp256k1::Secp256k1,
        util::key::{PrivateKey, PublicKey},
        util::psbt::PartiallySignedTransaction,
        Network,
    };
    use rstest::rstest;
    use std::str::FromStr;

    use super::*;
    use crate::blockchain::{noop_progress, ElectrumBlockchain};
    use crate::database::memory::MemoryDatabase;
    use crate::electrum_client::{Client, ElectrumApi};
    use crate::wallet::test::get_funded_wallet;
    use crate::SignOptions;

    #[test]
    fn verify_existing_proof_testnet() {
        let psbt = r#"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"#;
        let psbt = base64::decode(psbt).unwrap();
        let psbt = PartiallySignedTransaction::consensus_decode(&psbt[..]).unwrap();

        // redundant detailed verification start
        let tx = psbt.clone().extract_tx();
        assert_eq!(tx.input.len(), 3);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 0);
        assert_eq!(psbt.inputs[1].partial_sigs.len(), 3);
        assert_eq!(psbt.inputs[2].partial_sigs.len(), 3);
        // redundant detailed verification end

        let client = Client::new("ssl://electrum.blockstream.info:60002").unwrap();
        let address = bitcoin::Address::from_str("2Mtkk3kjyN8hgdGXPuJCNnwS3BBY4K2frhY").unwrap();
        let unspents = client
            .script_list_unspent(&address.script_pubkey())
            .unwrap();
        let outpoints: Vec<_> = unspents
            .iter()
            .map(|utxo| OutPoint {
                txid: utxo.tx_hash,
                vout: utxo.tx_pos as u32,
            })
            .collect();

        let message = "Stored in SEBA Bank AG cold storage";
        let balance = client.script_get_balance(&address.script_pubkey()).unwrap();
        let spendable = verify_proof(&psbt, message, outpoints, Network::Testnet).unwrap();
        assert_eq!(spendable, balance.confirmed + balance.unconfirmed as u64);
    }

    #[rstest(
        descriptor,
        case("wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)"),
        case("wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))"),     // and(pk(Alice),older(6))
        case("wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),after(100000)))") // and(pk(Alice),after(100000))
    )]
    fn test_proof(descriptor: &'static str) -> Result<(), Error> {
        let (wallet, _, _) = get_funded_wallet(descriptor);
        let balance = wallet.get_balance()?;

        let message = "This belongs to me.";
        let mut psbt = wallet.create_proof(&message)?;
        let num_inp = psbt.inputs.len();
        assert!(
            num_inp > 1,
            "num_inp is {} but should be more than 1",
            num_inp
        );

        let finalized = wallet.sign(
            &mut psbt,
            SignOptions {
                trust_witness_utxo: true,
                ..Default::default()
            },
        )?;
        let num_sigs = psbt
            .inputs
            .iter()
            .fold(0, |acc, i| acc + i.partial_sigs.len());
        assert_eq!(num_sigs, (num_inp - 1) * 1);
        assert_eq!(finalized, true);

        let spendable = wallet.verify_proof(&psbt, &message)?;
        assert_eq!(spendable, balance);

        Ok(())
    }

    #[test]
    #[should_panic(expected = "ProofOfReservesInvalid(\"Challenge txin mismatch\")")]
    fn tampered_proof_message() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);
        let balance = wallet.get_balance().unwrap();

        let message_alice = "This belongs to Alice.";
        let mut psbt_alice = wallet.create_proof(&message_alice).unwrap();

        let signopt = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };
        let _finalized = wallet.sign(&mut psbt_alice, signopt.clone()).unwrap();

        let spendable = wallet.verify_proof(&psbt_alice, &message_alice).unwrap();
        assert_eq!(spendable, balance);

        // change the message
        let message_bob = "This belongs to Bob.";
        let psbt_bob = wallet.create_proof(&message_bob).unwrap();
        psbt_alice.global.unsigned_tx.input[0].previous_output =
            psbt_bob.global.unsigned_tx.input[0].previous_output;
        psbt_alice.inputs[0].witness_utxo = psbt_bob.inputs[0].witness_utxo.clone();

        let res_alice = wallet.verify_proof(&psbt_alice, &message_alice);
        let res_bob = wallet.verify_proof(&psbt_alice, &message_bob);
        assert!(res_alice.is_err());
        assert!(res_bob.is_err());
        res_alice.unwrap();
        res_bob.unwrap();
    }

    #[test]
    #[should_panic(expected = "ProofOfReservesInvalid(\"Witness and legacy input found")]
    fn tampered_proof_witness_and_legacy() {
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet, _, _) = get_funded_wallet(descriptor);
        let balance = wallet.get_balance().unwrap();

        let message = "This belongs to Alice.";
        let mut psbt = wallet.create_proof(&message).unwrap();

        let signopt = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };
        let _finalized = wallet.sign(&mut psbt, signopt.clone()).unwrap();

        let spendable = wallet.verify_proof(&psbt, &message).unwrap();
        assert_eq!(spendable, balance);

        // add a legacy input to the existing segwit input
        let descriptor_legacy = "pkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let (wallet_legacy, _, _) = get_funded_wallet(descriptor_legacy);
        let mut psbt_legacy = wallet_legacy.create_proof(&message).unwrap();
        let _finalized = wallet_legacy.sign(&mut psbt_legacy, signopt).unwrap();

        psbt.inputs[1].non_witness_utxo = psbt_legacy.inputs[1].non_witness_utxo.clone();

        wallet.verify_proof(&psbt, &message).unwrap();
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

        let client = Client::new("ssl://electrum.blockstream.info:60002")?;
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
        assert!(
            balance >= 410000 && balance <= 420000,
            "balance is {} but should be between 410000 and 420000",
            balance
        );

        let message = "All my precious coins";
        let mut psbt = wallet1.create_proof(message)?;
        let num_inp = psbt.inputs.len();
        assert!(
            num_inp > 1,
            "num_inp is {} but should be more than 1",
            num_inp
        );

        // returns a tuple with the counts of (partial_sigs, final_script_sig, final_script_witness)
        let count_signatures = |psbt: &PSBT| {
            psbt.inputs.iter().fold((0usize, 0, 0), |acc, i| {
                (
                    acc.0 + i.partial_sigs.len(),
                    acc.1 + if i.final_script_sig.is_some() { 1 } else { 0 },
                    acc.2
                        + if i.final_script_witness.is_some() {
                            1
                        } else {
                            0
                        },
                )
            })
        };

        let signopts = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };
        let finalized = wallet1.sign(&mut psbt, signopts.clone())?;
        assert_eq!(count_signatures(&psbt), ((num_inp - 1) * 1, 1, 0));
        assert_eq!(finalized, false);

        let finalized = wallet2.sign(&mut psbt, signopts.clone())?;
        assert_eq!(
            count_signatures(&psbt),
            ((num_inp - 1) * 2, num_inp, num_inp - 1)
        );
        assert_eq!(finalized, true);

        // 2 signatures are enough. Just checking what happens...
        let finalized = wallet3.sign(&mut psbt, signopts.clone())?;
        assert_eq!(
            count_signatures(&psbt),
            ((num_inp - 1) * 2, num_inp, num_inp - 1)
        );
        assert_eq!(finalized, true);

        let finalized = wallet1.finalize_psbt(&mut psbt, signopts)?;
        assert_eq!(
            count_signatures(&psbt),
            ((num_inp - 1) * 2, num_inp, num_inp - 1)
        );
        assert_eq!(finalized, true);

        let spendable = wallet1.verify_proof(&psbt, &message)?;
        assert_eq!(spendable, balance);

        Ok(())
    }
}
