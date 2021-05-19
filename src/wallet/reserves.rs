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
        transaction::{OutPoint, TxIn, TxOut},
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
        // ToDo: verify that the proof inputs were spendable at the block height of the proof
        let outpoints = self
            .list_unspent()?
            .iter()
            .map(|utxo| utxo.outpoint)
            .collect();

        verify_proof(psbt, message, outpoints, self.network)
    }
}

/// Make sure this is a proof, and not a spendable transaction.
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
    // ToDo: verify that the proof inputs were spendable at the block height of the proof
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
    if let Some((i, inp)) = psbt
        .inputs
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_i, inp)| inp.partial_sigs.len() == 0)
    {
        return Err(Error::ProofOfReservesInvalid(format!(
            "Found an input that is not signed at #{} : {:?}",
            i, inp
        )));
    }

    // Verify other inputs against prevouts and calculate the amount.
    // ToDo: make sure this is enough to verify the signatures
    let serialized_tx = serialize(&tx);
    if let Some((i, res)) = psbt
        .inputs
        .iter()
        .zip(tx.input.iter())
        .enumerate()
        .map(|(i, (psbt_in, tx_in))| {
            if let Some(utxo) = &psbt_in.witness_utxo {
                (
                    i,
                    &utxo.script_pubkey,
                    utxo.value,
                )
            } else if let Some(nwtx) = &psbt_in.non_witness_utxo {
                let outp = &nwtx.output[tx_in.previous_output.vout as usize];
                (
                    i,
                    &outp.script_pubkey,
                    outp.value,
                )
            } else {
                panic!("must be either witness or legacy");
            }
        })
        .map(|(i, script, value)| {
            (
                i,
                bitcoinconsensus::verify(
                    script.to_bytes().as_slice(),
                    value,
                    &serialized_tx,
                    i,
                ),
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
        consensus::{encode::Decodable, Encodable},
        secp256k1::Secp256k1,
        util::key::{PrivateKey, PublicKey},
        util::psbt::PartiallySignedTransaction,
        Network,
    };
    use rstest::rstest;
    use std::{
        fs::{self, File},
        io::Write,
        str::FromStr,
    };

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
        let message = "SEBA Cold Storage 2021-04-01";
        let network = Network::Testnet;
        let address = bitcoin::Address::from_str("2Mtkk3kjyN8hgdGXPuJCNnwS3BBY4K2frhY").unwrap();

        let client = Client::new("ssl://electrum.blockstream.info:60002").unwrap();
        let balance = client.script_get_balance(&address.script_pubkey()).unwrap();

        // redundant detailed verification start
        let tx = psbt.clone().extract_tx();

        assert_eq!(tx.input.len(), 3);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 3);
        assert_eq!(psbt.inputs[1].partial_sigs.len(), 3);
        assert_eq!(psbt.inputs[2].partial_sigs.len(), 3);

        // redundant detailed verification end

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

        let spendable = verify_proof(&psbt, message, outpoints, network).unwrap();
        assert_eq!(spendable, balance.confirmed + balance.unconfirmed as u64);
    }

    #[rstest(
        descriptor,
//        case("wpkh(xprv9s21ZrQH143K4CTb63EaMxja1YiTnSEWKMbn23uoEnAzxjdUJRQkazCAtzxGm4LSoTSVTptoV9RbchnKPW9HxKtZumdyxyikZFDLhogJ5Uj/44'/0'/0'/0/*)"),
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
        assert_eq!(count_signatures(&psbt), ((num_inp - 1) * 2, num_inp, num_inp - 1));
        assert_eq!(finalized, true);

        let finalized = wallet3.sign(&mut psbt, signopts.clone())?;
        assert_eq!(count_signatures(&psbt), ((num_inp - 1) * 2, num_inp, num_inp - 1));
        assert_eq!(finalized, true);

        let finalized = wallet1.finalize_psbt(&mut psbt, signopts)?;
        assert_eq!(count_signatures(&psbt), ((num_inp - 1) * 2, num_inp, num_inp - 1));
        if !finalized {
            write_to_temp_file(&psbt);
        }
        assert_eq!(finalized, true);

        let spendable = wallet1.verify_proof(&psbt, &message)?;
        assert_eq!(spendable, balance);

        Ok(())
    }

    fn write_to_temp_file(psbt: &PSBT) {
        let data = encode_tx(psbt).unwrap();
        let filename = "/tmp/psbt";
        #[allow(unused_must_use)]
        fs::remove_file(filename);
        let mut file = File::create(&filename).unwrap();
        file.write_all(&data).unwrap();
        file.sync_all().unwrap();
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
