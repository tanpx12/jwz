import { APIResponse } from "./APIResponse";

export function buildResponse(status: number, data: Object, message: string) {
  return new APIResponse(status, (data), message);
}

export function buildExceptionMessage(status: number, message: string) {
  return new APIResponse(status, {}, message);
}

export function buildErrorMessage(status: number, err: Error | string, message: string) {
  if (typeof err == 'string') {
    return new APIResponse(status, { error: err }, message);
  }
  return new APIResponse(status, { error: err.message }, message);
}