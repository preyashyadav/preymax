import { loadConfig, saveConfig } from '../core/config.js';
import { paths } from '../core/paths.js';

const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

/**
 * `preymax shadow on|off` and `preymax relay enable|disable`.
 *
 * v1 required hand-editing two unrelated keys (`notify.transport: none` plus a
 * sub-second `decisionTimeoutMs`) to get shadow mode, which was easy to set
 * wrong and easy to forget to revert — handoff bug 4. One flag now, and the
 * daemon reads it on the next call.
 */

function restartHint(): void {
  console.log(`${DIM}restart the daemon to pick this up:${RESET}`);
  console.log(`  launchctl kickstart -k gui/$(id -u)/com.preymax.daemon`);
}

export function runShadow(arg: string | undefined): number {
  const cfg = loadConfig();

  if (arg === undefined || arg === 'status') {
    console.log(cfg.shadow ? `shadow mode: ${GREEN}on${RESET}` : `shadow mode: ${YELLOW}off${RESET}`);
    console.log(
      cfg.shadow
        ? `  escalations are logged and fall straight through to the normal prompt.\n` +
          `  nothing is summarized, nothing is sent, no terminal ever stalls.`
        : `  escalations are handled normally${cfg.relay.enabled ? ' and pushed to the relay' : ''}.`,
    );
    return 0;
  }

  if (arg !== 'on' && arg !== 'off') {
    console.error('usage: preymax shadow on|off');
    return 2;
  }

  const next = arg === 'on';
  if (cfg.shadow === next) {
    console.log(`shadow mode is already ${arg}`);
    return 0;
  }

  cfg.shadow = next;
  saveConfig(cfg);
  console.log(`shadow mode: ${next ? `${GREEN}on${RESET}` : `${YELLOW}off${RESET}`}`);
  if (next) {
    console.log('  measuring only. Nothing will be summarized, pushed, or blocked on.');
  } else if (!cfg.relay.enabled) {
    console.log(`  ${DIM}note: the relay is still disabled, so escalations return`);
    console.log(`  ask immediately. Enable it with: preymax relay enable${RESET}`);
  }
  restartHint();
  return 0;
}

export function runRelay(action: string | undefined, publicBaseUrl?: string): number {
  const cfg = loadConfig();

  if (action === undefined || action === 'status') {
    console.log(
      cfg.relay.enabled ? `relay: ${GREEN}enabled${RESET}` : `relay: ${YELLOW}disabled${RESET}`,
    );
    console.log(`  transport:  ${cfg.notify.transport}`);
    console.log(`  approve URL: ${cfg.publicBaseUrl ?? '(not set — notifications are read-only)'}`);
    if (cfg.shadow) {
      console.log(`  ${YELLOW}shadow mode is on, which overrides this${RESET}`);
    }
    return 0;
  }

  if (action !== 'enable' && action !== 'disable') {
    console.error('usage: preymax relay enable|disable|status [--public-url URL]');
    return 2;
  }

  const enable = action === 'enable';
  cfg.relay = { ...cfg.relay, enabled: enable };
  if (enable) {
    if (publicBaseUrl) cfg.publicBaseUrl = publicBaseUrl;
    if (cfg.notify.transport === 'none') cfg.notify.transport = 'ntfy';
    // v1's shadow hack left this at 1ms; a relay with no time to answer is
    // indistinguishable from no relay at all.
    if (cfg.decisionTimeoutMs < 5_000) cfg.decisionTimeoutMs = 60_000;
    cfg.shadow = false;
  }
  saveConfig(cfg);

  console.log(`relay: ${enable ? `${GREEN}enabled${RESET}` : `${YELLOW}disabled${RESET}`}`);
  if (enable) {
    console.log(`  transport:       ${cfg.notify.transport}`);
    console.log(`  decision timeout: ${cfg.decisionTimeoutMs}ms`);
    console.log(`  approve URL:     ${cfg.publicBaseUrl ?? '(not set)'}`);
    if (!cfg.publicBaseUrl) {
      console.log('');
      console.log('  Notifications will be read-only until the phone can reach the daemon.');
      console.log('  The daemon speaks plain HTTP, so terminate TLS with Tailscale Serve:');
      console.log(`    ${DIM}tailscale serve --bg --https=443 http://127.0.0.1:${cfg.port}${RESET}`);
      console.log(
        `    ${DIM}preymax relay enable --public-url https://<mac>.<tailnet>.ts.net${RESET}`,
      );
      console.log(`  ${DIM}(no port in that URL — Serve is fronting it on 443)${RESET}`);
    }
    console.log('');
    console.log(`  shadow mode turned off. Config: ${paths.config()}`);
  }
  restartHint();
  return 0;
}
