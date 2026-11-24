import { AxiosError, AxiosHeaders, type AxiosResponse } from "axios";

export function httpError(status: number, data: unknown = {}): AxiosError {
  const config = { headers: new AxiosHeaders() };
  const response = { status, data, statusText: "", headers: {}, config } as AxiosResponse;
  return new AxiosError(`HTTP ${status}`, "ERR_BAD_RESPONSE", config, {}, response);
}

export function networkError(): AxiosError {
  return new AxiosError("Network Error", "ERR_NETWORK", { headers: new AxiosHeaders() }, {});
}
