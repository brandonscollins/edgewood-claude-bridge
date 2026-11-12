<?php
/**
 * Plugin Name: Edgewood Claude Bridge
 * Description: Lets Claude Code manage this site's Divi pages, templates and settings through the WordPress API. Works only for the "claude" user. Every change is logged under Tools > Claude Bridge.
 * Version: 0.1.1
 * Author: Edgewood Community Church
 * Requires at least: 6.4
 * Requires PHP: 7.4
 * License: GPLv2 or later
 */

if (!defined('ABSPATH')) exit;

const ECB_VERSION = '0.1.1';
const ECB_USER = 'claude';
const ECB_NS = 'ecb/v1';
const ECB_LOG_MAX = 300;

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
	return ecb_is_claude() && ecb_enabled() && current_user_can('manage_options');
}

/* ---------- change log: every write Claude makes through any API route ---------- */

add_filter('rest_post_dispatch', function ($response, $server, $request) {
	if ($request->get_method() === 'GET' || !ecb_is_claude()) return $response;
	$log = get_option('ecb_log', []);
	$log[] = [
		'time'   => current_time('mysql'),
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

/* ---------- Tools > Claude Bridge: on/off switch and change log ---------- */

add_action('admin_menu', function () {
	add_management_page('Claude Bridge', 'Claude Bridge', 'manage_options', 'ecb', 'ecb_admin_page');
});

function ecb_admin_page() {
	if (!current_user_can('manage_options')) return;
	if (isset($_POST['ecb_toggle']) && check_admin_referer('ecb_toggle')) {
		update_option('ecb_enabled', ecb_enabled() ? '0' : '1', false);
	}
	$on = ecb_enabled();
	$log = array_reverse(get_option('ecb_log', []));
	echo '<div class="wrap"><h1>Claude Bridge</h1>';
	echo '<p>Lets Claude Code edit this site as the <strong>' . esc_html(ECB_USER) . '</strong> user. Version ' . esc_html(ECB_VERSION) . '.</p>';
	echo '<p>Claude access is <strong style="color:' . ($on ? '#276838">ON' : '#b32d2e">OFF') . '</strong>.</p>';
	echo '<form method="post">';
	wp_nonce_field('ecb_toggle');
	submit_button($on ? 'Turn Claude access off' : 'Turn Claude access on', $on ? 'secondary' : 'primary', 'ecb_toggle', false);
	echo '</form><p>To cut Claude off for good, delete its Application Password under Users &gt; ' . esc_html(ECB_USER) . '.</p>';
	echo '<h2>Recent changes by Claude</h2><table class="widefat striped"><thead><tr><th>When</th><th>Action</th><th>What</th><th>Result</th></tr></thead><tbody>';
	if (!$log) echo '<tr><td colspan="4">No changes yet.</td></tr>';
	foreach (array_slice($log, 0, 100) as $e) {
		printf('<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>',
			esc_html($e['time']), esc_html($e['method']), esc_html($e['route']), esc_html($e['status']));
	}
	echo '</tbody></table></div>';
}

register_activation_hook(__FILE__, function () { register_uninstall_hook(__FILE__, 'ecb_uninstall'); });
function ecb_uninstall() {
	global $wpdb;
	$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'ecb\\_%'");
}
