import express from 'express'
import { AuthRouter } from './routers/AuthRouter';
class Server {
  public app: express.Application;
  constructor() {
    this.app = express();
    this.config();
    this.routes();
  }

  public routes(): void {
    this.app.use("/api/auth", new AuthRouter().router)
  }

  public config(): void {
    this.app.set("port", 5000);
    this.app.use(express.json());
  }

  public start(): void {
    this.app.listen(this.app.get("port"), () => {
      console.log("Service is running on port: ", this.app.get("port"));
    })
  }
}

function startServer(): void {
  const server = new Server();
  server.start()
}

startServer()