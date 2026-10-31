// Content operations via the gateway (monas-sdk content controller).
// The SDK does: CEK gen → AES-256-GCM → SHA-256 CID → storage → state-node
// register/update/delete (+ signing via account). All content is base64url.
import { gateway } from "./http";

export interface ContentMetadata {
  name?: string;
  content_type?: string;
  created_at?: string;
  updated_at?: string;
}

export interface CreateContentOutput {
  /** The SDK's file key: what every later owner-side call addresses. */
  file_id: string;
  content_id: string; // plain content id of the created version
  remote_content_id?: string; // state-node Content Network id
  created_at?: string;
}

export function createContent(input: { contentBase64Url: string; name: string; contentType?: string }) {
  return gateway<CreateContentOutput>("/content", {
    method: "POST",
    timestamp: true,
    body: {
      content: input.contentBase64Url,
      metadata: { name: input.name, content_type: input.contentType },
    },
  });
}

export interface GetContentOutput {
  content_id: string;
  content: string; // decrypted, base64url
  metadata?: ContentMetadata;
}

export function getContent(fileId: string) {
  return gateway<GetContentOutput>(`/content/${encodeURIComponent(fileId)}`, {
    method: "GET",
  });
}

export interface UpdateContentOutput {
  file_id: string; // unchanged by the edit
  previous_version_id: string;
  version_id: string; // plain content id of the new version
  updated_at?: string;
}

export function updateContent(input: {
  fileId: string;
  remoteContentId: string;
  contentBase64Url: string;
  name?: string;
}) {
  return gateway<UpdateContentOutput>(
    `/content/${encodeURIComponent(input.fileId)}`,
    {
      method: "PUT",
      timestamp: true,
      body: {
        file_id: input.fileId,
        remote_content_id: input.remoteContentId,
        content: input.contentBase64Url,
        metadata: input.name ? { name: input.name } : undefined,
      },
    },
  );
}

export interface DeleteContentOutput {
  content_id: string;
  deleted: boolean;
  deleted_at?: string;
}

export function deleteContent(input: { fileId: string; remoteContentId: string }) {
  return gateway<DeleteContentOutput>(
    `/content/${encodeURIComponent(input.fileId)}`,
    {
      method: "DELETE",
      timestamp: true,
      body: {
        file_id: input.fileId,
        remote_content_id: input.remoteContentId,
      },
    },
  );
}
