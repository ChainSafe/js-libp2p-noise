type LabelsGeneric = Record<string, string | undefined>;
type CollectFn<Labels extends LabelsGeneric> = (metric: Gauge<Labels>) => void;

interface Gauge<Labels extends LabelsGeneric = never> {
  // Sorry for this mess, `prom-client` API choices are not great
  // If the function signature was `inc(value: number, labels?: Labels)`, this would be simpler
  inc(value?: number): void;
  inc(labels: Labels, value?: number): void;
  inc(arg1?: Labels | number, arg2?: number): void;

  dec(value?: number): void;
  dec(labels: Labels, value?: number): void;
  dec(arg1?: Labels | number, arg2?: number): void;

  set(value: number): void;
  set(labels: Labels, value: number): void;
  set(arg1?: Labels | number, arg2?: number): void;

  addCollect(collectFn: CollectFn<Labels>): void;
}

export interface Metrics {
  xxHandshakeSuccesses: Gauge;
  xxHandshakeErrors: Gauge;
  encryptedPackets: Gauge;
  decryptedPackets: Gauge;
  decryptErrors: Gauge;
}
