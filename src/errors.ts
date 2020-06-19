export class FailedIKError extends Error {
  public initialMsg: string;

  constructor (initialMsg: string, message?: string) {
    super(message)

    this.initialMsg = initialMsg
    this.name = 'FailedIKhandshake'
  }
}
