
import fs from 'fs'
import path from 'path'
//ts-ignore
const snarkjs = require('snarkjs')


export async function verifyProof(verification_key: Object, public_signals: string[], proof: Object): Promise<boolean> {
  try {
    return await snarkjs.groth16.verify(verification_key, public_signals, proof)
  }
  catch (err) {
    throw err
  }
}

