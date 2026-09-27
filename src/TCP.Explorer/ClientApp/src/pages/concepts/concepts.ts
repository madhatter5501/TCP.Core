import type { ComponentType } from 'react';
import { DatagramArticle } from './DatagramArticle';
import { GlossaryArticle } from './GlossaryArticle';
import { PduNamesArticle } from './PduNamesArticle';

export interface Concept {
  slug: string;
  title: string;
  summary: string;
  Article: ComponentType;
}

/** Add an article here and it gets a route, a sidebar entry and a card. */
export const concepts: Concept[] = [
  { slug: 'pdus', title: 'One payload, five names', summary: 'Frame, packet, datagram, segment: the PDU at each layer.', Article: PduNamesArticle },
  { slug: 'datagram', title: 'What is a datagram?', summary: 'Self-addressed, best-effort units, and how they differ from TCP’s stream.', Article: DatagramArticle },
  { slug: 'glossary', title: 'Glossary', summary: 'FCS, MSS, DF, TTL… every term the Explorer uses, A to Z.', Article: GlossaryArticle }
];
