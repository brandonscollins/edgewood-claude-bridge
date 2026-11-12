<?php
/**
 * Plugin Name: Edgewood Claude Bridge
 * Description: Lets Claude manage this site's Divi pages, templates and settings through the WordPress API: the "claude" user, plus invited administrators signed in through the Edgewood connector as themselves. Every change is logged under Tools > Claude Bridge.
 * Version: 0.3.0
 * Author: Edgewood Community Church
 * Requires at least: 6.4
 * Requires PHP: 7.4
 * License: GPLv2 or later
 */

if (!defined('ABSPATH')) exit;

const ECB_VERSION = '0.3.0';
const ECB_USER = 'claude';
const ECB_NS = 'ecb/v1';
const ECB_LOG_MAX = 300;
const ECB_REPO = 'brandonscollins/edgewood-claude-bridge';

/* ---------- who is Claude, and is the bridge on ---------- */

function ecb_is_claude() {
	$u = wp_get_current_user();
	return $u && $u->exists() && $u->user_login === ECB_USER;
}

function ecb_enabled() {
	return get_option('ecb_enabled', '1') === '1';
}

// The off switch: when the bridge is off, the claude user is refused by the whole WordPress API.
add_filter('rest_authentication_errors', function ($result) {
	if (is_wp_error($result) || ecb_enabled() || !ecb_is_claude()) return $result;
	return new WP_Error('ecb_disabled', 'Claude access is turned off in Tools > Claude Bridge.', ['status' => 403]);
}, 100);

function ecb_permission() {
	$u = wp_get_current_user();
	return $u->exists() && ecb_enabled() && (ecb_is_claude() || ecb_person_on($u->ID)) && current_user_can('manage_options');
}

/* ---------- people: invited administrators who use their own Claude through the Edgewood connector ---------- */

// Admins switched on under Tools > Claude Bridge. Stored as [user id => true].
function ecb_person_on($id) {
	$people = get_option('ecb_people', []);
	return !empty($people[$id]) && user_can($id, 'manage_options');
}

// The connector (a small helper on Cloudflare) signs in each person with their Edgewood Microsoft account, then
// sends requests that say who the person is, signed with a key only it and this site know. Headers:
//   X-ECB-Person: email   X-ECB-Time: unix seconds   X-ECB-Signature: hex HMAC-SHA256(key, "time\nemail\nMETHOD\nrequest URI\nsha256(body)")
// Media uploads must send the file as the raw body (not a multipart form), so the body hash covers it.
// A valid request runs as that person's own WordPress account. Only the bridge routes and media uploads accept it,
// so the key can never reach users, plugins or any other part of WordPress.
// ponytail: a captured request could be replayed for 5 minutes; HTTPS makes capture unlikely. Add a used-signature list if that changes.
function ecb_helper_user() {
	if (empty($_SERVER['HTTP_X_ECB_PERSON'])) return null;
	$fail = function ($msg) { $GLOBALS['ecb_helper_error'] = new WP_Error('ecb_helper', $msg, ['status' => 401]); return null; };
	$key = get_option('ecb_helper_key', '');
	if (strlen($key) < 32) return $fail('The Edgewood connector is not set up on this site yet (Tools > Claude Bridge).');
	$uri = $_SERVER['REQUEST_URI'] ?? '';
	// The route must START the address after /wp-json (no ?rest_route= form), so nothing else can borrow the key.
	$path = rawurldecode((string) parse_url($uri, PHP_URL_PATH));
	if (strpos($path, '/.') !== false || !preg_match('#^(/[^/]+)*?/wp-json/(ecb/v1|wp/v2/media)(/|$)#', $path)) return $fail('The connector can only use the bridge and media routes.');
	$email = strtolower(trim($_SERVER['HTTP_X_ECB_PERSON']));
	$time = (int) ($_SERVER['HTTP_X_ECB_TIME'] ?? 0);
	if (abs(time() - $time) > 300) return $fail('Request is too old. Check the connector clock.');
	$body = (string) file_get_contents('php://input');
	$msg = $time . "\n" . $email . "\n" . strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') . "\n" . $uri . "\n" . hash('sha256', $body);
	if (!hash_equals(hash_hmac('sha256', $msg, $key), strtolower((string) ($_SERVER['HTTP_X_ECB_SIGNATURE'] ?? '')))) return $fail('Bad connector signature.');
	$user = get_user_by('email', $email);
	if (!$user) return $fail("No WordPress account uses $email.");
	if (!ecb_person_on($user->ID)) return $fail('This person is not switched on under Tools > Claude Bridge, or is not an administrator.');
	$GLOBALS['ecb_via_helper'] = true;
	return $user;
}

// Runs after WordPress's own sign-ins (application passwords run at 20). A request with a password never reaches this.
add_filter('determine_current_user', function ($id) {
	if ($id) return $id;
	$user = ecb_helper_user();
	return $user ? $user->ID : $id;
}, 30);

add_filter('rest_authentication_errors', function ($result) {
	wp_get_current_user(); // make sure the connector check above has run
	if (!empty($GLOBALS['ecb_helper_error'])) return $GLOBALS['ecb_helper_error'];
	if (!empty($GLOBALS['ecb_via_helper']) && !ecb_enabled()) return new WP_Error('ecb_disabled', 'Claude access is turned off in Tools > Claude Bridge.', ['status' => 403]);
	return $result;
}, 101);

// Second lock: check the route WordPress actually runs, in case the web server rewrote the address.
add_filter('rest_pre_dispatch', function ($result, $server, $request) {
	if (empty($GLOBALS['ecb_via_helper']) || preg_match('#^/(ecb/v1|wp/v2/media)(/|$)#', $request->get_route())) return $result;
	return new WP_Error('ecb_helper', 'The connector can only use the bridge and media routes.', ['status' => 403]);
}, 10, 3);

/* ---------- change log: every write Claude makes through any API route ---------- */

add_filter('rest_post_dispatch', function ($response, $server, $request) {
	if ($request->get_method() === 'GET' || !(ecb_is_claude() || !empty($GLOBALS['ecb_via_helper']))) return $response;
	$log = get_option('ecb_log', []);
	$log[] = [
		'time'   => current_time('mysql'),
		'who'    => wp_get_current_user()->display_name,
		'method' => $request->get_method(),
		'route'  => $request->get_route(),
		'status' => $response instanceof WP_HTTP_Response ? $response->get_status() : 0,
	];
	update_option('ecb_log', array_slice($log, -ECB_LOG_MAX), false);
	return $response;
}, 10, 3);

/* ---------- which content Claude may edit ---------- */

function ecb_type_allowed($type) {
	if (!post_type_exists($type)) return false;
	// Pages, posts, and Divi's own types (library, theme builder templates and layouts).
	return in_array($type, ['page', 'post'], true) || strpos($type, 'et_') === 0;
}

function ecb_meta_key_allowed($key) {
	// Divi's page settings and builder data only (e.g. _et_pb_use_builder, _et_header_layout_id).
	return (bool) preg_match('/^_?et_/', $key);
}

function ecb_option_allowed($name) {
	if (!preg_match('/^(et_|et-|builder_|divi_)/', $name)) return false;
	// Never expose license keys or account details.
	return !preg_match('/api_key|google_api|license|updates_options|username|password|token|secret/i', $name);
}

/* ---------- routes ---------- */

add_action('rest_api_init', function () {
	$p = 'ecb_permission';
	register_rest_route(ECB_NS, '/status', ['methods' => 'GET', 'callback' => 'ecb_status', 'permission_callback' => $p]);
	register_rest_route(ECB_NS, '/options', ['methods' => 'GET', 'callback' => 'ecb_options_list', 'permission_callback' => $p]);
	register_rest_route(ECB_NS, '/options/(?P<name>[A-Za-z0-9_\-]+)', [
		['methods' => 'GET', 'callback' => 'ecb_option_get', 'permission_callback' => $p],
		['methods' => 'POST', 'callback' => 'ecb_option_set', 'permission_callback' => $p],
	]);
	register_rest_route(ECB_NS, '/items/(?P<type>[a-z0-9_\-]+)', [
		['methods' => 'GET', 'callback' => 'ecb_items_list', 'permission_callback' => $p],
		['methods' => 'POST', 'callback' => 'ecb_item_save', 'permission_callback' => $p],
	]);
	register_rest_route(ECB_NS, '/items/(?P<type>[a-z0-9_\-]+)/(?P<id>\d+)', [
		['methods' => 'GET', 'callback' => 'ecb_item_get', 'permission_callback' => $p],
		['methods' => 'POST', 'callback' => 'ecb_item_save', 'permission_callback' => $p],
		['methods' => 'DELETE', 'callback' => 'ecb_item_trash', 'permission_callback' => $p],
	]);
	register_rest_route(ECB_NS, '/cache/clear', ['methods' => 'POST', 'callback' => 'ecb_cache_clear', 'permission_callback' => $p]);
	// Lets Claude make WordPress notice a new release right away; installing it still takes an admin's click.
	register_rest_route(ECB_NS, '/update-check', ['methods' => 'POST', 'callback' => 'ecb_check_now', 'permission_callback' => $p]);
});

function ecb_status() {
	$theme = wp_get_theme();
	$parent = $theme->parent() ?: $theme;
	if (!function_exists('get_plugins')) require_once ABSPATH . 'wp-admin/includes/plugin.php';
	$active = [];
	foreach (get_option('active_plugins', []) as $file) {
		$data = get_plugin_data(WP_PLUGIN_DIR . '/' . $file, false, false);
		$active[$file] = $data['Version'];
	}
	return [
		'bridge'      => ECB_VERSION,
		'you'         => wp_get_current_user()->user_login,
		'viaConnector'=> !empty($GLOBALS['ecb_via_helper']),
		'wordpress'   => get_bloginfo('version'),
		'php'         => PHP_VERSION,
		'theme'       => $theme->get('Name') . ' ' . $theme->get('Version'),
		'parentTheme' => $parent->get('Name') . ' ' . $parent->get('Version'),
		'builder'     => defined('ET_BUILDER_VERSION') ? ET_BUILDER_VERSION : null,
		'diviTypes'   => array_values(array_filter(get_post_types(), 'ecb_type_allowed')),
		'plugins'     => $active,
	];
}

function ecb_options_list(WP_REST_Request $r) {
	global $wpdb;
	$rows = $wpdb->get_results("SELECT option_name, LENGTH(option_value) AS size FROM {$wpdb->options}
		WHERE option_name LIKE 'et\\_%' OR option_name LIKE 'et-%' OR option_name LIKE 'builder\\_%' OR option_name LIKE 'divi\\_%'
		ORDER BY option_name");
	$out = [];
	foreach ($rows as $row) if (ecb_option_allowed($row->option_name)) $out[$row->option_name] = (int) $row->size;
	return $out;
}

function ecb_option_get(WP_REST_Request $r) {
	$name = $r['name'];
	if (!ecb_option_allowed($name)) return new WP_Error('ecb_forbidden', 'This setting is not available to Claude.', ['status' => 403]);
	$value = get_option($name, null);
	if ($value === null) return new WP_Error('ecb_missing', 'No such setting.', ['status' => 404]);
	return ['name' => $name, 'value' => $value];
}

function ecb_option_set(WP_REST_Request $r) {
	$name = $r['name'];
	if (!ecb_option_allowed($name)) return new WP_Error('ecb_forbidden', 'This setting is not available to Claude.', ['status' => 403]);
	$body = $r->get_json_params();
	if (!is_array($body) || !array_key_exists('value', $body)) return new WP_Error('ecb_bad', 'Send {"value": ...}.', ['status' => 400]);
	// Keep the previous value so one bad write can be undone from the server side too.
	$old = get_option($name, null);
	if ($old !== null) update_option('ecb_prev_' . md5($name), ['name' => $name, 'time' => current_time('mysql'), 'value' => $old], false);
	update_option($name, $body['value']);
	return ['name' => $name, 'saved' => true];
}

function ecb_items_list(WP_REST_Request $r) {
	$type = $r['type'];
	if (!ecb_type_allowed($type)) return new WP_Error('ecb_forbidden', 'Claude cannot edit this kind of content.', ['status' => 403]);
	$posts = get_posts([
		'post_type'      => $type,
		'post_status'    => ['publish', 'draft', 'private', 'pending', 'future'],
		'posts_per_page' => min(200, max(1, (int) ($r['per_page'] ?: 100))),
		'paged'          => max(1, (int) ($r['page'] ?: 1)),
		's'              => (string) $r['search'],
		'orderby'        => 'ID',
		'order'          => 'ASC',
	]);
	return array_map(function ($p) {
		return ['id' => $p->ID, 'title' => $p->post_title, 'slug' => $p->post_name, 'status' => $p->post_status,
			'parent' => $p->post_parent, 'modified' => $p->post_modified, 'terms' => ecb_terms($p)];
	}, $posts);
}

function ecb_terms($post) {
	$out = [];
	foreach (get_object_taxonomies($post->post_type) as $tax) {
		$terms = wp_get_object_terms($post->ID, $tax, ['fields' => 'slugs']);
		if (!is_wp_error($terms) && $terms) $out[$tax] = $terms;
	}
	return $out;
}

function ecb_find($type, $id) {
	if (!ecb_type_allowed($type)) return new WP_Error('ecb_forbidden', 'Claude cannot edit this kind of content.', ['status' => 403]);
	$post = get_post((int) $id);
	if (!$post || $post->post_type !== $type || $post->post_status === 'trash') return new WP_Error('ecb_missing', 'Not found.', ['status' => 404]);
	return $post;
}

function ecb_item_get(WP_REST_Request $r) {
	$post = ecb_find($r['type'], $r['id']);
	if (is_wp_error($post)) return $post;
	$meta = [];
	foreach (get_post_meta($post->ID) as $key => $values) {
		if (ecb_meta_key_allowed($key)) $meta[$key] = maybe_unserialize($values[0]);
	}
	return [
		'id' => $post->ID, 'type' => $post->post_type, 'title' => $post->post_title, 'slug' => $post->post_name,
		'status' => $post->post_status, 'parent' => $post->post_parent, 'menu_order' => $post->menu_order,
		'template' => get_page_template_slug($post), 'modified' => $post->post_modified,
		'content' => $post->post_content, 'excerpt' => $post->post_excerpt, 'meta' => $meta, 'terms' => ecb_terms($post),
		'link' => get_permalink($post),
	];
}

function ecb_item_save(WP_REST_Request $r) {
	$type = $r['type'];
	if (!ecb_type_allowed($type)) return new WP_Error('ecb_forbidden', 'Claude cannot edit this kind of content.', ['status' => 403]);
	$b = $r->get_json_params() ?: [];
	$id = (int) $r['id'];
	if ($id) {
		$post = ecb_find($type, $id);
		if (is_wp_error($post)) return $post;
		// Refuse to overwrite a page someone changed after Claude last read it.
		if (!empty($b['expect_modified']) && $b['expect_modified'] !== $post->post_modified) {
			return new WP_Error('ecb_conflict', 'This item changed since Claude read it. Read it again first.', ['status' => 409, 'modified' => $post->post_modified]);
		}
	}
	$data = ['post_type' => $type];
	if ($id) $data['ID'] = $id;
	foreach (['title' => 'post_title', 'content' => 'post_content', 'excerpt' => 'post_excerpt', 'status' => 'post_status',
		'slug' => 'post_name', 'parent' => 'post_parent', 'menu_order' => 'menu_order'] as $in => $field) {
		if (array_key_exists($in, $b)) $data[$field] = $b[$in];
	}
	if (isset($data['post_status']) && !in_array($data['post_status'], ['publish', 'draft', 'private', 'pending'], true)) {
		return new WP_Error('ecb_bad', 'Status must be publish, draft, private or pending.', ['status' => 400]);
	}
	if (!$id && empty($data['post_status'])) $data['post_status'] = 'draft';
	// Check everything before writing anything, so a refused request changes nothing.
	foreach (array_keys((array) ($b['meta'] ?? [])) as $key) {
		if (!ecb_meta_key_allowed($key)) return new WP_Error('ecb_forbidden', "Meta key $key is not allowed.", ['status' => 403]);
	}
	foreach (array_keys((array) ($b['terms'] ?? [])) as $tax) {
		if (!is_object_in_taxonomy($type, $tax)) return new WP_Error('ecb_bad', "Taxonomy $tax does not apply here.", ['status' => 400]);
	}
	// wp_insert_post strips one level of slashes; Divi content is full of them, so add one first.
	$result = $id ? wp_update_post(wp_slash($data), true) : wp_insert_post(wp_slash($data), true);
	if (is_wp_error($result)) return $result;

	if (isset($b['template'])) update_post_meta($result, '_wp_page_template', sanitize_text_field($b['template']));
	foreach ((array) ($b['meta'] ?? []) as $key => $value) {
		if ($value === null) delete_post_meta($result, $key);
		else update_post_meta($result, $key, wp_slash($value));
	}
	foreach ((array) ($b['terms'] ?? []) as $tax => $slugs) {
		$set =wp_set_object_terms($result, (array) $slugs, $tax);
		if (is_wp_error($set)) return $set;
	}
	$r2 = new WP_REST_Request('GET');
	$r2->set_url_params(['type' => $type, 'id' => $result]);
	return ecb_item_get($r2);
}

function ecb_item_trash(WP_REST_Request $r) {
	$post = ecb_find($r['type'], $r['id']);
	if (is_wp_error($post)) return $post;
	// Trash only, never permanent delete: anything can be restored from the Trash.
	return ['id' => $post->ID, 'trashed' => (bool) wp_trash_post($post->ID)];
}

function ecb_cache_clear() {
	$done = [];
	if (class_exists('ET_Core_PageResource')) { ET_Core_PageResource::remove_static_resources('all', 'all', true); $done[] = 'divi'; }
	if (function_exists('sg_cachepress_purge_everything')) { sg_cachepress_purge_everything(); $done[] = 'siteground'; }
	elseif (function_exists('sg_cachepress_purge_cache')) { sg_cachepress_purge_cache(); $done[] = 'siteground'; }
	wp_cache_flush();
	$done[] = 'object-cache';
	return ['cleared' => $done];
}

/* ---------- updates from GitHub (shown on the Plugins page; an admin clicks "Update now") ---------- */

// Each GitHub release carries version.json and edgewood-claude-bridge.zip. Using github.com download
// links instead of the GitHub API avoids its per-server rate limit on shared hosting.
function ecb_latest_release($force = false) {
	$cached = get_site_transient('ecb_release');
	if (!$force && empty($_GET['force-check']) && is_array($cached)) return $cached;
	$res = wp_remote_get('https://github.com/' . ECB_REPO . '/releases/latest/download/version.json', ['timeout' => 10]);
	$data = json_decode(wp_remote_retrieve_body($res), true);
	if (is_wp_error($res) || wp_remote_retrieve_response_code($res) !== 200 || empty($data['version'])) return null;
	$release = [
		'version' => (string) $data['version'],
		'notes'   => (string) ($data['notes'] ?? ''),
		'package' => 'https://github.com/' . ECB_REPO . '/releases/download/v' . rawurlencode($data['version']) . '/edgewood-claude-bridge.zip',
	];
	set_site_transient('ecb_release', $release, HOUR_IN_SECONDS);
	return $release;
}

add_filter('pre_set_site_transient_update_plugins', function ($transient) {
	if (!is_object($transient)) return $transient;
	$release = ecb_latest_release();
	if (!$release) return $transient;
	$file = plugin_basename(__FILE__);
	$item = (object) ['slug' => 'edgewood-claude-bridge', 'plugin' => $file, 'new_version' => $release['version'],
		'package' => $release['package'], 'url' => 'https://github.com/' . ECB_REPO];
	if (version_compare($release['version'], ECB_VERSION, '>')) {
		$transient->response[$file] = $item;
		unset($transient->no_update[$file]);
	} else {
		$transient->no_update[$file] = $item;
		unset($transient->response[$file]);
	}
	return $transient;
});

// "View details" on the Plugins page.
add_filter('plugins_api', function ($result, $action, $args) {
	if ($action !== 'plugin_information' || ($args->slug ?? '') !== 'edgewood-claude-bridge') return $result;
	$release = ecb_latest_release() ?: ['version' => ECB_VERSION, 'notes' => '', 'package' => ''];
	return (object) ['name' => 'Edgewood Claude Bridge', 'slug' => 'edgewood-claude-bridge', 'version' => $release['version'],
		'download_link' => $release['package'], 'homepage' => 'https://github.com/' . ECB_REPO,
		'sections' => ['changelog' => nl2br(esc_html($release['notes'] ?: 'See GitHub for release notes.'))]];
}, 10, 3);

function ecb_check_now() {
	delete_site_transient('ecb_release');
	delete_site_transient('update_plugins');
	wp_update_plugins();
	$release = ecb_latest_release();
	return ['installed' => ECB_VERSION, 'latest' => $release['version'] ?? null,
		'update_available' => $release && version_compare($release['version'], ECB_VERSION, '>')];
}

add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) {
	$links[] = '<a href="' . esc_url(admin_url('tools.php?page=ecb')) . '">Settings and update check</a>';
	return $links;
});

/* ---------- Tools > Claude Bridge: on/off switch and change log ---------- */

add_action('admin_menu', function () {
	add_management_page('Claude Bridge', 'Claude Bridge', 'manage_options', 'ecb', 'ecb_admin_page');
});

function ecb_admin_page() {
	if (!current_user_can('manage_options')) return;
	if (isset($_POST['ecb_toggle']) && check_admin_referer('ecb_toggle')) {
		update_option('ecb_enabled', ecb_enabled() ? '0' : '1', false);
	}
	if (isset($_POST['ecb_people_save']) && check_admin_referer('ecb_people')) {
		$on = [];
		foreach ((array) ($_POST['ecb_people'] ?? []) as $id) if (user_can((int) $id, 'manage_options')) $on[(int) $id] = true;
		update_option('ecb_people', $on, false);
	}
	if (isset($_POST['ecb_key_save']) && check_admin_referer('ecb_key')) {
		$key = trim((string) wp_unslash($_POST['ecb_key'] ?? ''));
		if ($key === '' || preg_match('/^[a-f0-9]{64}$/', $key)) update_option('ecb_helper_key', $key, false);
		else echo '<div class="notice notice-error"><p>That key is not the right shape (64 letters and numbers, a to f and 0 to 9). Nothing was saved.</p></div>';
	}
	$check = null;
	if (isset($_POST['ecb_check']) && check_admin_referer('ecb_check')) $check = ecb_check_now();
	$on = ecb_enabled();
	$log = array_reverse(get_option('ecb_log', []));
	echo '<div class="wrap"><h1>Claude Bridge</h1>';
	if ($check) {
		$msg = $check['latest'] === null ? 'Could not reach GitHub. Try again in a minute.'
			: ($check['update_available'] ? 'Version ' . $check['latest'] . ' is available. <a href="' . esc_url(admin_url('plugins.php')) . '">Go to Plugins and click "Update now"</a>.'
			: 'You have the latest version (' . $check['installed'] . ').');
		echo '<div class="notice notice-info"><p>' . wp_kses($msg, ['a' => ['href' => []]]) . '</p></div>';
	}
	echo '<p>Lets Claude edit this site as the <strong>' . esc_html(ECB_USER) . '</strong> user, and lets the people checked below use their own Claude. Version ' . esc_html(ECB_VERSION) . '.</p>';
	echo '<p>Claude access is <strong style="color:' . ($on ? '#276838">ON' : '#b32d2e">OFF') . '</strong>.</p>';
	echo '<form method="post">';
	wp_nonce_field('ecb_toggle');
	submit_button($on ? 'Turn Claude access off' : 'Turn Claude access on', $on ? 'secondary' : 'primary', 'ecb_toggle', false);
	echo '</form><p>This switch covers everyone: the ' . esc_html(ECB_USER) . ' user and every person below. To cut the ' . esc_html(ECB_USER) . ' user off for good, delete its Application Password under Users &gt; ' . esc_html(ECB_USER) . '.</p>';

	echo '<h2>People who can use their own Claude</h2><p>Administrators only. A checked person can edit the site from Claude through the Edgewood connector, signed in with their Edgewood Microsoft account. Changes run as their own WordPress account and show their name in the log below. Their Microsoft email must match the email on their WordPress account.</p>';
	echo '<form method="post">';
	wp_nonce_field('ecb_people');
	$people = get_option('ecb_people', []);
	echo '<table class="widefat striped" style="max-width:640px"><thead><tr><th>Can use Claude</th><th>Name</th><th>Email</th></tr></thead><tbody>';
	foreach (get_users(['role' => 'administrator', 'orderby' => 'display_name']) as $u) {
		if ($u->user_login === ECB_USER) continue;
		printf('<tr><td><input type="checkbox" name="ecb_people[]" value="%d" %s></td><td>%s</td><td>%s</td></tr>',
			$u->ID, checked(!empty($people[$u->ID]), true, false), esc_html($u->display_name), esc_html($u->user_email));
	}
	echo '</tbody></table>';
	submit_button('Save people', 'primary', 'ecb_people_save');
	echo '</form>';

	$key = get_option('ecb_helper_key', '');
	echo '<h2>Connector key</h2><p>The secret the Edgewood connector uses to prove a request came from it. Status: <strong>'
		. ($key ? 'saved (ends in ' . esc_html(substr($key, -4)) . ')' : 'not set, so the connector cannot reach this site') . '</strong>. Paste a new key to replace it, or save an empty box to shut the connector out.</p>';
	echo '<form method="post">';
	wp_nonce_field('ecb_key');
	echo '<input type="password" name="ecb_key" autocomplete="off" style="width:36em" placeholder="Paste the key here">';
	submit_button('Save key', 'secondary', 'ecb_key_save', false);
	echo '</form>';
	echo '<h2>Updates</h2><p>WordPress checks GitHub about twice a day. To check right now:</p><form method="post">';
	wp_nonce_field('ecb_check');
	submit_button('Check for updates now', 'secondary', 'ecb_check', false);
	echo '</form>';
	echo '<h2>Recent changes by Claude</h2><table class="widefat striped"><thead><tr><th>When</th><th>Who</th><th>Action</th><th>What</th><th>Result</th></tr></thead><tbody>';
	if (!$log) echo '<tr><td colspan="5">No changes yet.</td></tr>';
	foreach (array_slice($log, 0, 100) as $e) {
		printf('<tr><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>',
			esc_html($e['time']), esc_html($e['who'] ?? ECB_USER), esc_html($e['method']), esc_html($e['route']), esc_html($e['status']));
	}
	echo '</tbody></table></div>';
}

register_activation_hook(__FILE__, function () { register_uninstall_hook(__FILE__, 'ecb_uninstall'); });
function ecb_uninstall() {
	global $wpdb;
	$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'ecb\\_%'");
}
