import { Router } from "express";
import { AuthController } from "../controllers/AuthController";

export class AuthRouter {
  public router: Router;
  public authController = new AuthController();

  constructor() {
    this.router = Router();
    this.routers();
  }

  routers(): void {
    this.router.post("/authentication", this.authController.authentication)
    this.router.post("/authorization", this.authController.authorization)
  }
}