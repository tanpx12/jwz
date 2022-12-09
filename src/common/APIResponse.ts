export class APIResponse {
  status: number;
  data: Object;
  message: string;
  constructor(_status: number, _data: Object, _message: string) {
    this.status = _status;
    this.data = _data;
    this.message = _message;
  }
}