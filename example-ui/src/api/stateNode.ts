// State / version operations via the gateway (monas-sdk state controller).
import { gateway } from "./http";

export interface GetLatestVersionOutput {
  content_id: string;
  latest_version: string;
  updated_at?: string;
}

export function getLatestVersion(contentId: string) {
  return gateway<GetLatestVersionOutput>("/state/latest-version", {
    method: "POST",
    timestamp: true,
    body: { content_id: contentId },
  });
}

export interface GetHistoryOutput {
  content_id: string;
  versions: string[];
}

export function getHistory(contentId: string, limit = 100) {
  return gateway<GetHistoryOutput>("/state/history", {
    method: "POST",
    timestamp: true,
    body: { content_id: contentId, limit },
  });
}

export interface VerifyIntegrityOutput {
  valid: boolean;
  computed_hash: string;
  reason?: string;
}

export function verifyIntegrity(input: {
  contentId: string;
  contentBase64Url: string;
  expectedVersion?: string;
}) {
  return gateway<VerifyIntegrityOutput>("/state/verify-integrity", {
    method: "POST",
    timestamp: true,
    body: {
      content_id: input.contentId,
      content: input.contentBase64Url,
      expected_version: input.expectedVersion,
    },
  });
}
