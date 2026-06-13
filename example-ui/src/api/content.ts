// Content operations via the gateway (monas-sdk content controller).
// The SDK does: CEK gen → AES-256-CTR → SHA-256 CID → storage → state-node
// register/update/delete (+ signing via account). All content is base64url.
import { gateway } from "./http";

export interface ContentMetadata {
  name?: string;
  content_type?: string;
  created_at?: string;
  updated_at?: string;
}

export interface CreateContentOutput {
  content_id: string; // local id (encCid)
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

export function getContent(localContentId: string) {
  return gateway<GetContentOutput>(`/content/${encodeURIComponent(localContentId)}`, {
    method: "GET",
  });
}

export interface UpdateContentOutput {
  series_id: string;
  previous_version_id: string;
  version_id: string; // new local id
  updated_at?: string;
}

export function updateContent(input: {
  localContentId: string;
  remoteContentId: string;
  contentBase64Url: string;
  name?: string;
}) {
  return gateway<UpdateContentOutput>(
    `/content/${encodeURIComponent(input.localContentId)}`,
    {
      method: "PUT",
      timestamp: true,
      body: {
        local_content_id: input.localContentId,
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

export function deleteContent(input: { localContentId: string; remoteContentId: string }) {
  return gateway<DeleteContentOutput>(
    `/content/${encodeURIComponent(input.localContentId)}`,
    {
      method: "DELETE",
      timestamp: true,
      body: {
        local_content_id: input.localContentId,
        remote_content_id: input.remoteContentId,
      },
    },
  );
}
