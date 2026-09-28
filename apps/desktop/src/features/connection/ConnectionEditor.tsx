import { useRef, useState, type FormEvent } from "react";
import { Alert, Button, Checkbox, PasswordInput, TextInput } from "@mantine/core";
import { desktopApi } from "../../lib/desktop-api";
import type { DesktopState } from "../../models/topology";
import type { TunnelConnection, TunnelProfileRequest, TunnelProvider } from "../../models/connections-tools";
import { useProduct } from "../../i18n/product";
import { useConnectionsTools } from "../../i18n/connections-tools";
import { WorkspaceDialog } from "../workspace/WorkspaceDialog";

const TUNNEL_ID_PATTERN = /^[A-Za-z0-9_-]+$/;

export function ConnectionEditor({ profile, onState, onClose }: { profile: TunnelConnection | null; onState: (state: DesktopState) => void; onClose: () => void }) {
  const p = useProduct(); const c = useConnectionsTools();
  const [name, setName] = useState(profile?.name || "");
  const [provider, setProvider] = useState<TunnelProvider>(profile?.provider ?? "openai");
  const [tunnelId, setTunnelId] = useState(profile?.tunnel_id || "");
  const [apiKey, setApiKey] = useState("");
  const [autostart, setAutostart] = useState(profile?.autostart ?? true);
  const [busy, setBusy] = useState(false); const [failed, setFailed] = useState(false);
  const submitted = useRef(false);
  const cloudflare = provider === "cloudflare";
  // A saved profile's provider is part of its identity: its environment file and
  // managed service are bound to exactly one transport. An existing connection
  // therefore reports its provider instead of offering a switch the backend
  // would reject; switching means deleting this connection and adding a new one.
  const providerFixed = profile !== null;
  const trimmedId = tunnelId.trim();
  // A Cloudflare named Tunnel token already identifies the tunnel, so its name
  // or ID is only an optional label. An OpenAI Secure MCP Tunnel needs its
  // issued ID.
  const tunnelIdValid = cloudflare ? trimmedId === "" || TUNNEL_ID_PATTERN.test(trimmedId) : TUNNEL_ID_PATTERN.test(trimmedId);
  const credentialSupplied = Boolean(profile?.credential_present) || Boolean(apiKey.trim());
  const submit = async (event: FormEvent) => {
    event.preventDefault(); if (submitted.current) return;
    submitted.current = true; setBusy(true); setFailed(false);
    const request: TunnelProfileRequest = { id: profile?.id ?? null, name: name.trim(), provider, tunnel_id: trimmedId, api_key: apiKey || null, autostart, expected_revision: profile?.revision ?? null };
    setApiKey("");
    try { onState(await desktopApi.saveTunnelProfile(request)); onClose(); }
    catch { setFailed(true); }
    finally { request.api_key = null; submitted.current = false; setBusy(false); }
  };
  return <WorkspaceDialog title={profile ? `${p("edit")} ${profile.name}` : c("addConnection")} onClose={onClose} busy={busy}>
    <form className="profile-editor" onSubmit={event => void submit(event)} aria-busy={busy}>
      <TextInput className="field-group" id="connection-profile-name" label={c("name")} aria-label={c("name")} name="name" value={name} onChange={event => setName(event.currentTarget.value)} required maxLength={160} disabled={busy} autoFocus />
      {providerFixed
        ? <div className="field-group"><label>{c("provider")}</label><p data-webcodex-control="connection-provider">{cloudflare ? c("providerCloudflare") : c("providerOpenAi")}</p><small>{c("providerFixed")}</small></div>
        : <div className="field-group"><label htmlFor="connection-profile-provider">{c("provider")}</label>
            <select id="connection-profile-provider" name="provider" value={provider} onChange={event => setProvider(event.currentTarget.value as TunnelProvider)} disabled={busy} data-webcodex-control="connection-provider">
              <option value="openai">{c("providerOpenAi")}</option>
              <option value="cloudflare">{c("providerCloudflare")}</option>
            </select>
            <small>{cloudflare ? c("providerCloudflareHelp") : c("providerOpenAiHelp")}</small>
          </div>}
      <TextInput className="field-group" id="connection-profile-tunnel-id" label={cloudflare ? c("tunnelNameOptional") : "Tunnel ID"} aria-label={cloudflare ? c("tunnelNameOptional") : "Tunnel ID"} name="tunnel_id" value={tunnelId} onChange={event => setTunnelId(event.currentTarget.value)} required={!cloudflare} maxLength={256} pattern="(?:[A-Za-z0-9_]|-)+" spellCheck={false} autoCapitalize="none" disabled={busy} />
      <PasswordInput className="field-group" id="connection-profile-api-key" label={cloudflare ? c("tunnelToken") : "API Key"} aria-label={cloudflare ? c("tunnelToken") : "API Key"} name="api_key" value={apiKey} onChange={event => setApiKey(event.currentTarget.value)} required={!profile?.credential_present} maxLength={8192} autoComplete="new-password" spellCheck={false} disabled={busy} description={profile?.credential_present ? p("savedKey") : undefined} />
      <Checkbox className="profile-checkbox" id="connection-profile-autostart" label={c("autostart")} checked={autostart} onChange={event => setAutostart(event.currentTarget.checked)} disabled={busy} />
      {failed && <Alert color="red" role="alert">{c("operationFailed")}</Alert>}
      <div className="connection-actions"><Button type="submit" className="primary-button" disabled={busy || !name.trim() || !tunnelIdValid || !credentialSupplied}>{c("saveApply")}</Button><Button type="button" className="secondary-button" variant="default" disabled={busy} onClick={onClose}>{p("cancel")}</Button></div>
    </form>
  </WorkspaceDialog>;
}
