export class FailedIKError extends Error {
  public initialMsg;

  constructor(initialMsg, message?: string) {
    super(message);

    this.initialMsg = initialMsg;
    this.name = "FailedIKhandshake";
  }
};
