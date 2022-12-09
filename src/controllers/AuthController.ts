import { Request, Response, NextFunction } from "express";
import { buildErrorMessage, buildResponse } from "../common/ResponseBuilder";
import { Token } from "../../jwz";
import { execSync } from 'child_process'
import fs from 'fs'
import path from 'path'

export class AuthController {
  authentication(req: Request, res: Response, next: NextFunction) {
    let { proof, public_signals, circuitId, schema, algorithm, payload } = req.body;
    if (!circuitId || !proof || !public_signals || !schema || !algorithm || !payload) {
      res.send(buildErrorMessage(400, "Invalid request", "Unable to authenticated"))
      return;
    }
    else {
      try {
        fs.writeFileSync(path.resolve('./build/proof.json'), JSON.stringify(proof), 'utf-8');
        fs.writeFileSync(path.resolve('./build/public.json'), JSON.stringify(public_signals), 'utf-8');

        let isValid = execSync('npx snarkjs groth16 verify ./build/verification_key.json ./build/public.json ./build/proof.json');
        if (isValid.includes("OK")) {
          let token = new Token(algorithm, circuitId, schema, payload);
          token.zkProof = {
            proof: proof,
            public_signals: public_signals
          }
          let compressedToken = token.compress();
          res.send(buildResponse(200, { token: compressedToken }, "Authenticated"))
          return;
        }
      } catch (err) {
        res.send(buildErrorMessage(400, "Invalid proof", "Unable to authenticated"))
        throw err;
      }

    }
  }
  authorization(req: Request, res: Response, next: NextFunction) {

  }
}