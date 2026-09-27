/** Mirrors the JSON records in TransmissionSimulation.cs. */

export interface SimulationRequest { scenario: ScenarioId; message: string; payloadBytes: number; mtu: number }

export interface TraceEvent { timeMs: number; kind: string; message: string }

export interface PacketField { name: string; value: string; offset: number; bytes: number }

export type Delivery = 'Delivered' | 'Dropped' | 'Corrupted';

export interface CapturedFrame {
  number: number;
  timeMs: number;
  from: string;
  to: string;
  protocol: string;
  delivery: Delivery;
  explanation: string;
  length: number;
  sentHex: string;
  receivedHex: string;
  fields: PacketField[];
}

export interface SimulationResult {
  scenario: ScenarioId;
  sendAccepted: boolean;
  echoAnswered: boolean;
  replyVerified: boolean;
  outcome: string;
  payloadBytes: number;
  mtu: number;
  virtualDurationMs: number;
  events: TraceEvent[];
  frames: CapturedFrame[];
  tcpRetransmissions: number;
}

export type ScenarioId =
  | 'tcp' | 'tcp-loss' | 'tcp-checksum' | 'tcp-window' | 'tcp-refused'
  | 'ping' | 'fragment' | 'df' | 'checksum' | 'loss' | 'arp-loss';
