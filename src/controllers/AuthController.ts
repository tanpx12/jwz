import { Request, Response, NextFunction } from "express";
import { buildErrorMessage, buildResponse } from "../common/ResponseBuilder";
import { JWZ } from "../../jwz";
import fs from 'fs'
import path from 'path'

let vk = JSON.parse(fs.readFileSync(path.resolve("./build/verification_key.json"), 'utf-8'))
enum Role {
  Admin = "1",
  Operator = "2"
}

export class AuthController {
  async authentication(req: Request, res: Response, next: NextFunction) {
    let { proof, public_signals, circuitId, schema, algorithm, payload } = req.body;
    if (!circuitId || !proof || !public_signals || !schema || !algorithm || !payload) {
      res.send(buildErrorMessage(400, "Invalid request", "Unable to login"))
      return;
    }
    else {
      try {
        let token = new JWZ(algorithm, circuitId, schema, payload);
        token.zkProof = {
          proof: proof,
          public_signals: public_signals
        }
        let isValid = await token.verifyProof(vk)
        if (isValid) {
          let compressedToken = token.compress();
          res.send(buildResponse(200, { token: compressedToken }, "Login successful"))
          return;
        } else {
          res.send(buildErrorMessage(400, "Invalid proof", "Unable to login"))
        }
      } catch (err) {
        res.send(buildErrorMessage(400, "Invalid proof", "Unable to login"))
        throw err;
      }
    }
  }
  async authorization(req: Request, res: Response, next: NextFunction) {
    let { token } = req.body
    if (!token) {
      res.send(buildErrorMessage(401, "Invalid token", "Unauthorized"))
    } else {
      try {
        let parsedToken = JWZ.parse(token);

        let isValid = await parsedToken.verifyToken(vk, Role.Admin, "123456", "123456", 3600000)
        if (isValid) {
          res.send(buildResponse(200, { msg: "Authorized successful" }, "Authorized"))
          return;
        }
        else {
          res.send(buildErrorMessage(401, "Invalid token", "Unauthorized"))
          return;
        }
      } catch (err) {
        res.send(buildErrorMessage(401, "Invalid token", "Unauthorized"))
        throw err
      }
    }
  }
}