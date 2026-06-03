import { Client, GatewayIntentBits, SlashCommandBuilder, REST, Routes, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, PermissionFlagsBits, ModalBuilder, TextInputBuilder, TextInputStyle } from 'discord.js';
import Database from 'better-sqlite3';

const db = new Database('./data.db');
const ADMIN_IDS = ['630804914473402398', '1508050922322788518'];

const {
  DISCORD_BOT_TOKEN,
  DISCORD_BOT_CLIENT_ID,
  DISCORD_GUILD_ID,
  ACTIVEVM_PANEL_URL,
  ACTIVEVM_API_KEY,
} = process.env;

// ─── ActiveVm API ──────────────────────────────────────────────────────────────

async function activeVmRequest(method, endpoint, body = null) {
  const { default: fetch } = await import('node-fetch');
  const res = await fetch(`${ACTIVEVM_PANEL_URL}/api/application${endpoint}`, {
    method,
    headers: {
      'Authorization': `Bearer ${ACTIVEVM_API_KEY}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  if (res.status === 204) return null;
  return res.json();
}

// ─── ヘルパー ──────────────────────────────────────────────────────────────────

function isSuperAdmin(userId) {
  return ADMIN_IDS.includes(userId);
}

function isAdmin(userId) {
  const user = db.prepare('SELECT is_admin FROM users WHERE discord_id = ?').get(userId);
  return user?.is_admin === 1;
}

function requireAdminCheck(interaction) {
  if (!isAdmin(interaction.user.id) && !isSuperAdmin(interaction.user.id)) {
    interaction.reply({ content: '❌ このコマンドは管理者専用です。', ephemeral: true });
    return false;
  }
  return true;
}

function requireSuperAdminCheck(interaction) {
  if (!isSuperAdmin(interaction.user.id)) {
    interaction.reply({ content: '❌ このコマンドはスーパー管理者専用です。', ephemeral: true });
    return false;
  }
  return true;
}

function expiryColor(expiresAt) {
  const daysLeft = (new Date(expiresAt) - Date.now()) / (1000 * 60 * 60 * 24);
  if (daysLeft <= 0) return 0xE74C3C;
  if (daysLeft <= 1) return 0xF39C12;
  return 0x2ECC71;
}

// ─── スラッシュコマンド定義 ────────────────────────────────────────────────────

const commands = [
  // ユーザー向け
  new SlashCommandBuilder()
    .setName('myservers')
    .setDescription('自分のサーバー一覧を表示します'),

  new SlashCommandBuilder()
    .setName('mystatus')
    .setDescription('自分のアカウント情報を表示します'),

  // 管理者向け
  new SlashCommandBuilder()
    .setName('user')
    .setDescription('ユーザー管理コマンド')
    .addSubcommand(sub => sub
      .setName('info')
      .setDescription('ユーザー情報を表示')
      .addUserOption(opt => opt.setName('target').setDescription('対象ユーザー').setRequired(true)))
    .addSubcommand(sub => sub
      .setName('ban')
      .setDescription('ユーザーをBAN')
      .addUserOption(opt => opt.setName('target').setDescription('対象ユーザー').setRequired(true))
      .addStringOption(opt => opt.setName('reason').setDescription('理由').setRequired(false)))
    .addSubcommand(sub => sub
      .setName('unban')
      .setDescription('BANを解除')
      .addUserOption(opt => opt.setName('target').setDescription('対象ユーザー').setRequired(true)))
    .addSubcommand(sub => sub
      .setName('setmax')
      .setDescription('最大サーバー数を変更')
      .addUserOption(opt => opt.setName('target').setDescription('対象ユーザー').setRequired(true))
      .addIntegerOption(opt => opt.setName('max').setDescription('上限数 (0-50)').setRequired(true).setMinValue(0).setMaxValue(50)))
    .addSubcommand(sub => sub
      .setName('addstaff')
      .setDescription('スタッフ（管理者）に昇格')
      .addUserOption(opt => opt.setName('target').setDescription('対象ユーザー').setRequired(true)))
    .addSubcommand(sub => sub
      .setName('list')
      .setDescription('全ユーザー一覧')),

  new SlashCommandBuilder()
    .setName('server')
    .setDescription('サーバー管理コマンド')
    .addSubcommand(sub => sub
      .setName('list')
      .setDescription('全サーバー一覧'))
    .addSubcommand(sub => sub
      .setName('extend')
      .setDescription('サーバーの期限を延長')
      .addIntegerOption(opt => opt.setName('id').setDescription('サーバーID').setRequired(true)))
    .addSubcommand(sub => sub
      .setName('delete')
      .setDescription('サーバーを削除')
      .addIntegerOption(opt => opt.setName('id').setDescription('サーバーID').setRequired(true))),

  new SlashCommandBuilder()
    .setName('specs')
    .setDescription('デフォルトスペック管理')
    .addSubcommand(sub => sub
      .setName('show')
      .setDescription('現在のデフォルトスペックを表示'))
    .addSubcommand(sub => sub
      .setName('set')
      .setDescription('デフォルトスペックを変更')
      .addIntegerOption(opt => opt.setName('cpu').setDescription('CPU (%)').setRequired(false).setMinValue(10).setMaxValue(2000))
      .addIntegerOption(opt => opt.setName('memory').setDescription('メモリ (MB)').setRequired(false).setMinValue(128))
      .addIntegerOption(opt => opt.setName('disk').setDescription('ディスク (MB)').setRequired(false).setMinValue(256))
      .addIntegerOption(opt => opt.setName('days').setDescription('デフォルト期間 (日)').setRequired(false).setMinValue(1).setMaxValue(30))
      .addIntegerOption(opt => opt.setName('maxservers').setDescription('ユーザーあたり最大数').setRequired(false).setMinValue(1).setMaxValue(20))),

  new SlashCommandBuilder()
    .setName('security')
    .setDescription('セキュリティ・DDoS対策管理')
    .addSubcommand(sub => sub
      .setName('stats')
      .setDescription('セキュリティ統計を表示'))
    .addSubcommand(sub => sub
      .setName('blockip')
      .setDescription('IPアドレスを手動ブロック')
      .addStringOption(opt => opt.setName('ip').setDescription('ブロックするIPアドレス').setRequired(true))
      .addStringOption(opt => opt.setName('reason').setDescription('理由').setRequired(false)))
    .addSubcommand(sub => sub
      .setName('unblockip')
      .setDescription('IPアドレスのブロックを解除')
      .addStringOption(opt => opt.setName('ip').setDescription('解除するIPアドレス').setRequired(true)))
    .addSubcommand(sub => sub
      .setName('blocklist')
      .setDescription('ブロック中のIPリスト')),

  new SlashCommandBuilder()
    .setName('stats')
    .setDescription('サービス全体の統計を表示'),

].map(cmd => cmd.toJSON());

// ─── Discord クライアント ──────────────────────────────────────────────────────

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
  ],
});

client.once('ready', async () => {
  console.log(`[BOT] Logged in as ${client.user.tag}`);

  // スラッシュコマンドを登録
  const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN);
  try {
    const route = DISCORD_GUILD_ID
      ? Routes.applicationGuildCommands(DISCORD_BOT_CLIENT_ID, DISCORD_GUILD_ID)
      : Routes.applicationCommands(DISCORD_BOT_CLIENT_ID);
    await rest.put(route, { body: commands });
    console.log(`[BOT] Slash commands registered (${commands.length} commands)`);
  } catch (e) {
    console.error('[BOT] Command registration failed:', e);
  }
});

// ─── インタラクションハンドラー ───────────────────────────────────────────────

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isChatInputCommand()) return;

  const { commandName } = interaction;

  try {
    // ── /myservers ────────────────────────────────────────────────
    if (commandName === 'myservers') {
      const servers = db.prepare(`
        SELECT * FROM servers WHERE owner_discord_id = ? AND is_deleted = 0
        ORDER BY created_at DESC
      `).all(interaction.user.id);

      if (servers.length === 0) {
        return interaction.reply({ content: '📭 現在アクティブなサーバーはありません。', ephemeral: true });
      }

      const embed = new EmbedBuilder()
        .setTitle('マイサーバー')
        .setColor(0x5B6AF5)
        .setTimestamp();

      for (const s of servers) {
        const daysLeft = ((new Date(s.expires_at) - Date.now()) / (1000 * 60 * 60 * 24)).toFixed(1);
        embed.addFields({
          name: `${s.name} (ID: ${s.id})`,
          value: `期限: ${new Date(s.expires_at).toLocaleDateString('ja-JP')} (残り ${daysLeft}日)\nPanel ID: \`${s.activevm_server_id?.slice(0,8) || 'pending'}\``,
          inline: false,
        });
      }

      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /mystatus ─────────────────────────────────────────────────
    if (commandName === 'mystatus') {
      const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(interaction.user.id);
      if (!user) {
        return interaction.reply({ content: '❌ アカウントが見つかりません。まずWebからログインしてください。', ephemeral: true });
      }
      const serverCount = db.prepare('SELECT COUNT(*) as c FROM servers WHERE owner_discord_id = ? AND is_deleted = 0').get(interaction.user.id).c;
      const embed = new EmbedBuilder()
        .setTitle('👤 アカウント情報')
        .setColor(user.is_banned ? 0xE74C3C : 0x5B6AF5)
        .addFields(
          { name: 'Discord', value: user.discord_username, inline: true },
          { name: '役割', value: user.is_admin ? '管理者' : 'ユーザー', inline: true },
          { name: 'ステータス', value: user.is_banned ? `🔴 BAN (${user.ban_reason})` : '🟢 正常', inline: true },
          { name: 'サーバー', value: `${serverCount} / ${user.max_servers}`, inline: true },
          { name: '登録日', value: new Date(user.created_at).toLocaleDateString('ja-JP'), inline: true },
        )
        .setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /user ─────────────────────────────────────────────────────
    if (commandName === 'user') {
      if (!requireAdminCheck(interaction)) return;
      const sub = interaction.options.getSubcommand();

      if (sub === 'info') {
        const target = interaction.options.getUser('target');
        const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(target.id);
        if (!user) return interaction.reply({ content: '❌ このユーザーはDBに登録されていません。', ephemeral: true });

        const serverCount = db.prepare('SELECT COUNT(*) as c FROM servers WHERE owner_discord_id = ? AND is_deleted = 0').get(target.id).c;
        const servers = db.prepare('SELECT * FROM servers WHERE owner_discord_id = ? AND is_deleted = 0').all(target.id);

        const embed = new EmbedBuilder()
          .setTitle(`👤 ${user.discord_username}`)
          .setColor(user.is_banned ? 0xE74C3C : 0x2ECC71)
          .setThumbnail(target.displayAvatarURL())
          .addFields(
            { name: 'Discord ID', value: `\`${user.discord_id}\``, inline: true },
            { name: '役割', value: user.is_admin ? '管理者' : 'ユーザー', inline: true },
            { name: 'ステータス', value: user.is_banned ? `🔴 BAN\n理由: ${user.ban_reason}` : '🟢 正常', inline: true },
            { name: 'サーバー数', value: `${serverCount} / ${user.max_servers}`, inline: true },
            { name: '登録日', value: new Date(user.created_at).toLocaleDateString('ja-JP'), inline: true },
          );

        if (servers.length > 0) {
          embed.addFields({
            name: 'アクティブサーバー',
            value: servers.map(s => `• **${s.name}** (残り${((new Date(s.expires_at)-Date.now())/(1000*60*60*24)).toFixed(1)}日)`).join('\n'),
          });
        }

        const row = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId(`ban_${target.id}`).setLabel('BAN').setStyle(ButtonStyle.Danger).setDisabled(user.is_banned || ADMIN_IDS.includes(target.id)),
          new ButtonBuilder().setCustomId(`unban_${target.id}`).setLabel('BAN解除').setStyle(ButtonStyle.Success).setDisabled(!user.is_banned),
        );

        return interaction.reply({ embeds: [embed], components: [row], ephemeral: true });
      }

      if (sub === 'ban') {
        const target = interaction.options.getUser('target');
        const reason = interaction.options.getString('reason') || 'No reason';
        if (ADMIN_IDS.includes(target.id)) return interaction.reply({ content: '❌ 管理者をBANすることはできません。', ephemeral: true });
        db.prepare('UPDATE users SET is_banned = 1, ban_reason = ? WHERE discord_id = ?').run(reason, target.id);
        return interaction.reply({ content: `✅ **${target.username}** をBANしました。\n理由: ${reason}`, ephemeral: false });
      }

      if (sub === 'unban') {
        const target = interaction.options.getUser('target');
        db.prepare('UPDATE users SET is_banned = 0, ban_reason = NULL WHERE discord_id = ?').run(target.id);
        return interaction.reply({ content: `✅ **${target.username}** のBANを解除しました。`, ephemeral: false });
      }

      if (sub === 'setmax') {
        const target = interaction.options.getUser('target');
        const max = interaction.options.getInteger('max');
        db.prepare('UPDATE users SET max_servers = ? WHERE discord_id = ?').run(max, target.id);
        return interaction.reply({ content: `✅ **${target.username}** の最大サーバー数を **${max}個** に変更しました。`, ephemeral: false });
      }

      if (sub === 'addstaff') {
        if (!requireSuperAdminCheck(interaction)) return;
        const target = interaction.options.getUser('target');
        db.prepare('UPDATE users SET is_admin = 1 WHERE discord_id = ?').run(target.id);
        return interaction.reply({ content: `✅ **${target.username}** を管理者に設定しました。`, ephemeral: false });
      }

      if (sub === 'list') {
        const users = db.prepare(`
          SELECT u.*, COUNT(s.id) as sc
          FROM users u
          LEFT JOIN servers s ON s.owner_discord_id = u.discord_id AND s.is_deleted = 0
          GROUP BY u.discord_id ORDER BY u.created_at DESC LIMIT 20
        `).all();

        const embed = new EmbedBuilder()
          .setTitle('ユーザー一覧 (最新20件)')
          .setColor(0x5B6AF5)
          .setDescription(
            users.map(u =>
              `${u.is_banned ? '🔴' : u.is_admin ? '🛡' : '🟢'} **${u.discord_username}** — サーバー: ${u.sc}/${u.max_servers}`
            ).join('\n') || 'ユーザーなし'
          )
          .setTimestamp();

        return interaction.reply({ embeds: [embed], ephemeral: true });
      }
    }

    // ── /server ───────────────────────────────────────────────────
    if (commandName === 'server') {
      if (!requireAdminCheck(interaction)) return;
      const sub = interaction.options.getSubcommand();

      if (sub === 'list') {
        const servers = db.prepare(`
          SELECT s.*, u.discord_username FROM servers s
          JOIN users u ON u.discord_id = s.owner_discord_id
          WHERE s.is_deleted = 0 ORDER BY s.created_at DESC LIMIT 20
        `).all();

        const embed = new EmbedBuilder()
          .setTitle('サーバー一覧 (最新20件)')
          .setColor(0x5B6AF5)
          .setDescription(
            servers.map(s => {
              const daysLeft = ((new Date(s.expires_at) - Date.now()) / (1000 * 60 * 60 * 24)).toFixed(1);
              const icon = daysLeft <= 0 ? '🔴' : daysLeft <= 1 ? '🟡' : '🟢';
              return `${icon} **${s.name}** (ID:${s.id}) — ${s.discord_username} — 残り${daysLeft}日`;
            }).join('\n') || 'サーバーなし'
          )
          .setTimestamp();

        return interaction.reply({ embeds: [embed], ephemeral: true });
      }

      if (sub === 'extend') {
        const id = interaction.options.getInteger('id');
        const server = db.prepare('SELECT * FROM servers WHERE id = ? AND is_deleted = 0').get(id);
        if (!server) return interaction.reply({ content: `❌ ID:${id} のサーバーが見つかりません。`, ephemeral: true });

        const specs = db.prepare('SELECT * FROM default_specs WHERE id = 1').get();
        const base = new Date(Math.max(new Date(server.expires_at), Date.now()));
        const newExpiry = new Date(base.getTime() + specs.duration_days * 24 * 60 * 60 * 1000);
        db.prepare('UPDATE servers SET expires_at = ? WHERE id = ?').run(newExpiry.toISOString(), id);

        return interaction.reply({
          content: `✅ **${server.name}** の期限を延長しました。\n新しい期限: **${newExpiry.toLocaleDateString('ja-JP')}**`,
          ephemeral: false,
        });
      }

      if (sub === 'delete') {
        const id = interaction.options.getInteger('id');
        const server = db.prepare('SELECT * FROM servers WHERE id = ? AND is_deleted = 0').get(id);
        if (!server) return interaction.reply({ content: `❌ ID:${id} のサーバーが見つかりません。`, ephemeral: true });

        const row = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId(`confirm_del_${id}`).setLabel(`削除する`).setStyle(ButtonStyle.Danger),
          new ButtonBuilder().setCustomId('cancel_del').setLabel('キャンセル').setStyle(ButtonStyle.Secondary),
        );

        return interaction.reply({
          content: `⚠️ **${server.name}** を本当に削除しますか？この操作は元に戻せません。`,
          components: [row],
          ephemeral: true,
        });
      }
    }

    // ── /specs ────────────────────────────────────────────────────
    if (commandName === 'specs') {
      if (!requireAdminCheck(interaction)) return;
      const sub = interaction.options.getSubcommand();

      if (sub === 'show') {
        const specs = db.prepare('SELECT * FROM default_specs WHERE id = 1').get();
        const embed = new EmbedBuilder()
          .setTitle('デフォルトスペック')
          .setColor(0x5B6AF5)
          .addFields(
            { name: 'CPU', value: `${specs.cpu}%`, inline: true },
            { name: 'メモリ', value: `${specs.memory} MB`, inline: true },
            { name: 'ディスク', value: `${specs.disk} MB`, inline: true },
            { name: 'デフォルト期間', value: `${specs.duration_days} 日`, inline: true },
            { name: '最大サーバー数/ユーザー', value: `${specs.max_servers_per_user} 個`, inline: true },
          )
          .setTimestamp();
        return interaction.reply({ embeds: [embed], ephemeral: true });
      }

      if (sub === 'set') {
        const specs = db.prepare('SELECT * FROM default_specs WHERE id = 1').get();
        const updates = {
          cpu:                interaction.options.getInteger('cpu')        ?? specs.cpu,
          memory:             interaction.options.getInteger('memory')     ?? specs.memory,
          disk:               interaction.options.getInteger('disk')       ?? specs.disk,
          duration_days:      interaction.options.getInteger('days')       ?? specs.duration_days,
          max_servers_per_user: interaction.options.getInteger('maxservers') ?? specs.max_servers_per_user,
        };
        db.prepare(`
          UPDATE default_specs SET cpu=?, memory=?, disk=?, duration_days=?, max_servers_per_user=? WHERE id=1
        `).run(updates.cpu, updates.memory, updates.disk, updates.duration_days, updates.max_servers_per_user);

        return interaction.reply({
          content: `✅ スペックを更新しました。\nCPU: ${updates.cpu}% | RAM: ${updates.memory}MB | Disk: ${updates.disk}MB | 期間: ${updates.duration_days}日 | 最大数: ${updates.max_servers_per_user}`,
          ephemeral: false,
        });
      }
    }

    // ── /security ─────────────────────────────────────────────────
    if (commandName === 'security') {
      if (!requireAdminCheck(interaction)) return;
      const sub = interaction.options.getSubcommand();

      if (sub === 'stats') {
        const blockedCount = db.prepare('SELECT COUNT(*) as c FROM blocked_ips').get().c;
        const recentErrors = db.prepare(`
          SELECT COUNT(*) as c FROM request_log WHERE ts > datetime('now', '-1 hour')
        `).get().c;
        const topIps = db.prepare(`
          SELECT ip, COUNT(*) as c FROM request_log
          WHERE ts > datetime('now', '-1 hour') AND status >= 400
          GROUP BY ip ORDER BY c DESC LIMIT 5
        `).all();
        const autoBlocked = db.prepare(`
          SELECT COUNT(*) as c FROM blocked_ips WHERE reason LIKE 'auto%'
        `).get().c;

        const embed = new EmbedBuilder()
          .setTitle('セキュリティ統計')
          .setColor(0xE74C3C)
          .addFields(
            { name: 'ブロック中IP数', value: `${blockedCount}`, inline: true },
            { name: '自動ブロック数', value: `${autoBlocked}`, inline: true },
            { name: '直近1hエラー数', value: `${recentErrors}`, inline: true },
          )
          .setTimestamp();

        if (topIps.length > 0) {
          embed.addFields({
            name: 'エラー上位IP (直近1h)',
            value: topIps.map(r => `\`${r.ip}\` — ${r.c}件`).join('\n'),
          });
        }

        return interaction.reply({ embeds: [embed], ephemeral: true });
      }

      if (sub === 'blockip') {
        const ip = interaction.options.getString('ip');
        const reason = interaction.options.getString('reason') || 'manual-bot';
        db.prepare('INSERT OR IGNORE INTO blocked_ips (ip, reason) VALUES (?, ?)').run(ip, reason);
        return interaction.reply({ content: `✅ \`${ip}\` をブロックしました。\n理由: ${reason}`, ephemeral: false });
      }

      if (sub === 'unblockip') {
        const ip = interaction.options.getString('ip');
        db.prepare('DELETE FROM blocked_ips WHERE ip = ?').run(ip);
        return interaction.reply({ content: `✅ \`${ip}\` のブロックを解除しました。`, ephemeral: false });
      }

      if (sub === 'blocklist') {
        const ips = db.prepare('SELECT * FROM blocked_ips ORDER BY blocked_at DESC LIMIT 25').all();
        const embed = new EmbedBuilder()
          .setTitle('🚫 ブロック中IPリスト')
          .setColor(0xE74C3C)
          .setDescription(
            ips.length > 0
              ? ips.map(r => `\`${r.ip}\` — ${r.reason} (${new Date(r.blocked_at).toLocaleDateString('ja-JP')})`).join('\n')
              : 'ブロック中のIPはありません'
          )
          .setTimestamp();
        return interaction.reply({ embeds: [embed], ephemeral: true });
      }
    }

    // ── /stats ────────────────────────────────────────────────────
    if (commandName === 'stats') {
      if (!requireAdminCheck(interaction)) return;

      const totalUsers   = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
      const totalServers = db.prepare('SELECT COUNT(*) as c FROM servers WHERE is_deleted = 0').get().c;
      const bannedUsers  = db.prepare('SELECT COUNT(*) as c FROM users WHERE is_banned = 1').get().c;
      const blockedIps   = db.prepare('SELECT COUNT(*) as c FROM blocked_ips').get().c;
      const expiringSoon = db.prepare(`
        SELECT COUNT(*) as c FROM servers
        WHERE is_deleted = 0 AND expires_at < datetime('now', '+1 day')
      `).get().c;

      const embed = new EmbedBuilder()
        .setTitle('ActiveVm 統計')
        .setColor(0x5B6AF5)
        .addFields(
          { name: '総ユーザー数', value: `${totalUsers}`, inline: true },
          { name: '稼働サーバー数', value: `${totalServers}`, inline: true },
          { name: 'BAN済ユーザー', value: `${bannedUsers}`, inline: true },
          { name: 'ブロック中IP', value: `${blockedIps}`, inline: true },
          { name: '期限切れ間近', value: `${expiringSoon}件 (24h以内)`, inline: true },
        )
        .setFooter({ text: 'ActiveVm Management' })
        .setTimestamp();

      return interaction.reply({ embeds: [embed], ephemeral: false });
    }

  } catch (e) {
    console.error(`[BOT] Error in command ${commandName}:`, e);
    if (!interaction.replied) {
      await interaction.reply({ content: '❌ エラーが発生しました。', ephemeral: true }).catch(() => {});
    }
  }
});

// ─── ボタンインタラクション ───────────────────────────────────────────────────

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isButton()) return;

  const { customId } = interaction;

  try {
    // BANボタン
    if (customId.startsWith('ban_')) {
      if (!isAdmin(interaction.user.id)) return interaction.reply({ content: '❌ 権限がありません。', ephemeral: true });
      const targetId = customId.replace('ban_', '');
      if (ADMIN_IDS.includes(targetId)) return interaction.reply({ content: '❌ 管理者をBANすることはできません。', ephemeral: true });
      db.prepare('UPDATE users SET is_banned = 1, ban_reason = ? WHERE discord_id = ?').run('Botによる手動BAN', targetId);
      return interaction.reply({ content: `✅ ユーザー (${targetId}) をBANしました。`, ephemeral: false });
    }

    // BAN解除ボタン
    if (customId.startsWith('unban_')) {
      if (!isAdmin(interaction.user.id)) return interaction.reply({ content: '❌ 権限がありません。', ephemeral: true });
      const targetId = customId.replace('unban_', '');
      db.prepare('UPDATE users SET is_banned = 0, ban_reason = NULL WHERE discord_id = ?').run(targetId);
      return interaction.reply({ content: `✅ ユーザー (${targetId}) のBANを解除しました。`, ephemeral: false });
    }

    // サーバー削除確認ボタン
    if (customId.startsWith('confirm_del_')) {
      if (!isAdmin(interaction.user.id)) return interaction.reply({ content: '❌ 権限がありません。', ephemeral: true });
      const id = parseInt(customId.replace('confirm_del_', ''));
      const server = db.prepare('SELECT * FROM servers WHERE id = ? AND is_deleted = 0').get(id);
      if (!server) return interaction.update({ content: '❌ サーバーが見つかりません。', components: [] });

      const { default: fetch } = await import('node-fetch');
      try {
        await fetch(`${ACTIVEVM_PANEL_URL}/api/application/servers/${server.activevm_server_id}`, {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${ACTIVEVM_API_KEY}` },
          signal: AbortSignal.timeout(10000),
        });
      } catch (e) {
        console.error('[BOT] Delete error:', e.message);
      }

      db.prepare('UPDATE servers SET is_deleted = 1 WHERE id = ?').run(id);
      return interaction.update({ content: `✅ **${server.name}** を削除しました。`, components: [] });
    }

    if (customId === 'cancel_del') {
      return interaction.update({ content: '✋ 削除をキャンセルしました。', components: [] });
    }

  } catch (e) {
    console.error('[BOT] Button error:', e);
    if (!interaction.replied) {
      await interaction.reply({ content: '❌ エラーが発生しました。', ephemeral: true }).catch(() => {});
    }
  }
});

// ─── 起動 ─────────────────────────────────────────────────────────────────────

if (!DISCORD_BOT_TOKEN) {
  console.error('[BOT] DISCORD_BOT_TOKEN が設定されていません。bot.jsを起動できません。');
  process.exit(1);
}

client.login(DISCORD_BOT_TOKEN).catch(e => {
  console.error('[BOT] Login failed:', e);
  process.exit(1);
});
