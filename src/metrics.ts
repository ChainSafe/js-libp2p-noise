export function getMetrics(register: MetricsRegister) {
  return {
    xxHandshakeSuccesses: register.gauge({
      name: "libp2p_noise_xxhandshake_successes_total",
      help: "Total count of noise xxHandshakes successes_",
    }),

    xxHandshakeErrors: register.gauge({
      name: "libp2p_noise_xxhandshake_error_total",
      help: "Total count of noise xxHandshakes errors",
    }),

    encryptedPackets: register.gauge({
      name: "libp2p_noise_encrypted_packets_total",
      help: "Total count of noise encrypted packets successfully",
    }),

    decryptedPackets: register.gauge({
      name: "libp2p_noise_decrypted_packets_total",
      help: "Total count of noise decrypted packets",
    }),

    decryptErrors: register.gauge({
      name: "libp2p_noise_decrypt_errors_total",
      help: "Total count of noise decrypt errors",
    }),
  };
}

export type Metrics = ReturnType<typeof getMetrics>;

export interface MetricsRegister {
  gauge<T extends LabelsGeneric>(config: GaugeConfig<T>): Gauge<T>;
}

interface GaugeConfig<Labels extends LabelsGeneric> {
  name: string;
  help: string;
  labelNames?: keyof Labels extends string ? Array<keyof Labels> : undefined;
}

type LabelsGeneric = Record<string, string | undefined>;
type CollectFn<Labels extends LabelsGeneric> = (metric: Gauge<Labels>) => void;

interface Gauge<Labels extends LabelsGeneric = never> {
  // Follows `prom-client` API choices, to require less middleware on consumer
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
