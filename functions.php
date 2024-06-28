<?php
use Dompdf\Dompdf;
require_once('do_action.php');
require_once('actions.php');

/*
uses:
cleanInput
sanitize
is_not_numeric
is_email
update_option
remove_option
get_option
get_user_meta
register_role
current_user_can
register_admin_page
register_admin_menu
unregister_admin_menu
register_admin_submenu
unregister_admin_submenu
has_child
render_page_scripts
*/

function cleanInput($input, $allowHtml = true) {
  $reserve = array('@<[\/\!]*?[^<>]*?>@si');   // Strip out HTML tags
  $search = array(
    '@<script[^>]*?>.*?</script>@si',   // Strip out javascript
    '@<style[^>]*?>.*?</style>@siU',    // Strip style tags properly
    '@<![\s\S]*?--[ \t\n\r]*>@'         // Strip multi-line comments
  );

  if(!$allowHtml) {
    $search = array_merge($reserve, $search);
  }

    $output = preg_replace($search, '', $input);
    return $output;
  }

function sanitize($input, $allowHtml = true, $query_obj = false) {

    if(!$query_obj) {
        $query_obj = new query;
    }

    if (is_array($input)) {
        foreach($input as $var=>$val) {
            $output[$var] = sanitize($val, $allowHtml, $query_obj);
        }
    }
    else {
        $output = $query_obj->_real_escape( $input );
    }
    return $output;
}

function removeslashes($string)
{
    $string=str_replace("\\n", "<br/>", $string);
    $string=str_replace("\\r", "", $string);
    $string=implode("",explode("\\",$string));
    return stripslashes(trim($string));
}

function _is_numeric($number) {
	if(!preg_match("/^[0-9]+$/", (string) $number)){
		return false;
	} else return !is_nan($number);
}

function is_email($email) {
    if (preg_match('/^(?:[\w\d-]+\.?)+@(?:(?:[\w\d]\-?)+\.)+\w{2,63}$/i', $email))
    {
        return true;
    } else return false;
}

function update_option($option, $option_value) {
	$options = new options;
	return $options->update_option($option, $option_value);
}

function remove_option($option) {
	$options = new options;
	return $options->remove_option($option);
}

function get_option($option) {
	$options = new options;
	return $options->get_option($option);
}

function update_record($record, $record_value) {
    $records = new records;
    return $records->update_record($record, $record_value);
}

function remove_record($record) {
    $records = new records;
    return $records->remove_record($record);
}

function get_record($record) {
    $records = new records;
    return $records->get_record($record);
}

function get_user_meta($selector) {
    $user = new user;
    return $user->get_user_meta($selector);
}

function register_role($role, $capabilities) {
    if(!is_array($capabilities))
        return false;
    $roles = get_option('user_roles');

    if(! $roles) {
        $roles = array();
    }

    $roles[$role] = $capabilities;

    update_option('user_roles', $roles);
}

function update_role($role, $capabilities) {
    $roles = get_option('user_roles');
    $capabilities = apply_filters("capabilities", ['role' => $role, 'capabilities' => $capabilities]);
    $capabilities = $capabilities['capabilities'];


    if(! $roles) {
        $ex_cap = array();
    } else {
        $ex_cap = (isset($roles[$role])) ? $roles[$role] : array();
    }
    if(is_array($capabilities)) {
        $new_cap = array_merge($ex_cap, $capabilities);
        if(_count($capabilities)) {
            $preset_cap = get_option("preset_user_roles");
            if($preset_cap && is_array($preset_cap) && _count($preset_cap)) {
                $cap = isset($preset_cap[$role]) ? $preset_cap[$role] : array();
                $cap = array_merge($cap, $capabilities);
                $preset_cap[$role] = array_unique($cap);
                update_option("preset_user_roles", $preset_cap);
            }
        }
    } else {
        $new_cap[] = $capabilities;
    }

    $roles[$role] = array_unique($new_cap);
    update_option('user_roles', $roles);
}

function apply_common_access($exclude = array(), $common_access = false) {
    if(!$common_access) {
        $common_access = get_option('common_access');
    }
    $roles = get_system_roles($exclude);
    if($roles) {
        if(_count($roles)) {
            foreach ($roles as $role_name => $role_slug) {
                update_role($role_slug, $common_access);
            }
        }
    }
}

function add_common_access( $common_access = array() ) {
    $common_access = ($option = get_option('common_access')) ? array_merge($common_access, $option) : $common_access;
    $common_access = array_unique($common_access);
    update_option('common_access', $common_access);
}

function get_role_name($role_slug) {
    $saved = get_option('role_names');
    if($saved && _count($saved)) {
        foreach ($saved as $_saved) {
            $_saved = trim_array(explode(",", $_saved));
            if($role_slug == $_saved[0]) return ucwords($_saved[1]);
        }
    }
    $role_name = ucwords(str_replace('_', ' ', $role_slug));  
    return $role_name;
}

function get_system_roles($exclude = array()) {
    $_roles;
    $roles = get_option('user_roles');
    if($roles) {
        if(_count($roles)) {
            foreach ($roles as $key => $value) {
                if(in_array($key, $exclude))
                    continue;
                $_roles[get_role_name($key)] = $key;
            }
        }
    }
    return $_roles;
}

function get_system_capabilities($roles = false) {
    if(!$roles) {
        $roles = get_option('user_roles');
    }
    $capabilities = array();
    if(_count($roles)) {
        foreach ($roles as $key => $value) {
            $capabilities = array_merge($capabilities, $value);
        }
    }
    return array_unique($capabilities);
}

function current_user_can($capabilities) {
    $session = Session::getInstance();

    if(!isset($session->id)) {
        return false;
    }
    $user_meta = get_user_meta($session->id);
    if(!isset($user_meta['role'])) {
        return false;
    }
    $role = $user_meta['role'];
    $roles = get_option('user_roles');
    if(!isset($roles[$role])) {
        return false;
    }
    if(strpos($capabilities, ",") !== false) {
        // or
        $arr = explode(",", $capabilities);
        $arr = trim_array($arr);
        if(!_count($arr)) return false;
        foreach ($arr as $cap) {
            if(in_array(strtolower($cap), $roles[$role])){
                return true;
            }
        }
    }
    if(strpos($capabilities, "+") !== false) {
        // and
        $arr = explode("+", $capabilities);
        $arr = trim_array($arr);
        if(!_count($arr)) return false;
        foreach ($arr as $cap) {
            if(!in_array(strtolower($cap), $roles[$role])){
                return false;
            }
        }
        return true;
    }
    if(in_array(strtolower($capabilities), $roles[$role])){
        return true;
    }
}

function user_can($user_meta, $capabilities) {
    if(!is_array($user_meta)) {
        $user_meta = get_user_meta($user_meta);
    }
    if(!isset($user_meta['role'])) {
        return false;
    }
    $role = $user_meta['role'];
    $roles = get_option('user_roles');
    if(!isset($roles[$role])) {
        return false;
    }
    if(strpos($capabilities, ",") !== false) {
        // or
        $arr = explode(",", $capabilities);
        $arr = trim_array($arr);
        if(!_count($arr)) return false;
        foreach ($arr as $cap) {
            if(in_array(strtolower($cap), $roles[$role])){
                return true;
            }
        }
    }
    if(strpos($capabilities, "+") !== false) {
        // and
        $arr = explode("+", $capabilities);
        $arr = trim_array($arr);
        if(!_count($arr)) return false;
        foreach ($arr as $cap) {
            if(!in_array(strtolower($cap), $roles[$role])){
                return false;
            }
        }
        return true;
    }
    if(in_array(strtolower($capabilities), $roles[$role])){
        return true;
    }
}

function register_admin_page($args) {
    $post = new post;
    if(!$post->search_post_by_permalink($args['permalink'])) :
        $args['type'] = 'page';
        $args['posted_on'] = time();
        $post->add_post($args);
    endif;
}

function unregister_admin_page($permalink) {
    $post = new post;
    if(!is_array($permalink)) {
        $post_id = $post->search_post_by_permalink($permalink);
        if($post_id)
            $post->drop_post($post_id);
    } else {
        foreach ($permalink as $key => $link) {
            $post_id = $post->search_post_by_permalink($link);
            if($post_id)
                $post->drop_post($post_id);
        }
    }
    
}

function add_page_loaders($permalink, $loader_url) {
    $post = new post;
    $post_id = $post->search_post_by_permalink($permalink);
    if($post_id) {
        $post->update_post_meta($post_id, ['loaders' => $loader_url]);
    }
}

function render_page_content($permalink, $params = array()) {
    $post = new post;
    $post_id = $post->search_post_by_permalink($permalink);
    $page_meta = $post->get_post_meta($post_id);
    $_GET = array_merge($_GET, $params);
    if(isset($page_meta['availability'])) {
        if($page_meta['availability'] == 'public') {
            if (function_exists($page_meta['callback'])) {
                do_action("before_render_public_content");
                do_action("before_render_content_".$permalink);
                $page_meta['callback']();
                do_action("after_render_public_content");
                do_action("after_render_content_".$permalink);
            } else echo "You have not created the function ".$page_meta['callback']." to display this page";
            return;
        }
    }
    if(current_user_can($page_meta['access'])) :
        if (function_exists($page_meta['callback'])) {
            do_action("before_render_content");
            do_action("before_render_content_".$permalink);
            echo $page_meta['callback']();
            do_action("after_render_content");
            do_action("after_render_content_".$permalink);
        } else echo "You have not created the function ".$page_meta['callback']." to display this content";
    else:
        echo '<i class="fas fa-warning text-yellow"></i> RESTRICTED: You are not allowed to view this content';
    endif;
}

function register_admin_menu($args) {
    if (get_option("stop_update_menu") && !DEVMODE) {
        return;
    }
    // acceptable args are: id, title, icon, page, class, access, condition
    if(!isset($args['id']))
        return false;
    $admin_menu = get_option('admin_menu');
    if(!$admin_menu) {
        $admin_menu = array();
    }
    if(isset($admin_menu[$args['id']])) {
        return;
        $the_menu = $admin_menu[$args['id']];
        if(isset($args['title'])) {
            $the_menu['title'] = $args['title'];
        }
        if(isset($args['icon'])) {
            $the_menu['icon'] = $args['icon'];
        }
        if(isset($args['page'])) {
            $the_menu['page'] = $args['page'];
        }
        if(isset($args['class'])) {
            $the_menu['class'] = $args['class'];
        }
        if(isset($args['access'])) {
            $the_menu['access'] = $args['access'];
        }
        if(isset($args['order'])) {
            $the_menu['order'] = $args['order'];
        }
        if(isset($args['condition'])) {
            $the_menu['condition'] = $args['condition'];
        } else $the_menu['condition'] = true;
        $admin_menu[$args['id']] = $the_menu;
        update_option('admin_menu', $admin_menu);
    } else {
        $the_menu = array();
        if(isset($args['id'])) {
            $the_menu['id'] = $args['id'];
        } else return false;
        if(isset($args['title'])) {
            $the_menu['title'] = $args['title'];
        } else return false;
        if(isset($args['icon'])) {
            $the_menu['icon'] = $args['icon'];
        }
        if(isset($args['page'])) {
            $the_menu['page'] = $args['page'];
        }
        if(isset($args['class'])) {
            $the_menu['class'] = $args['class'];
        }
        if(isset($args['access'])) {
            $the_menu['access'] = $args['access'];
        } else $the_menu['access'] = 'edit_options';
        if(isset($args['order'])) {
            $the_menu['order'] = $args['order'];
        }
        if(isset($args['condition'])) {
            $the_menu['condition'] = $args['condition'];
        } else $the_menu['condition'] = true;
        $admin_menu[$args['id']] = $the_menu;
        update_option('admin_menu', $admin_menu);
    }
}

function unregister_admin_menu($menu_id) {
    if (get_option("stop_update_menu") && !DEVMODE) {
        return;
    }
    $admin_menu = get_option('admin_menu');
    if(!is_array($menu_id)) {
        if(isset($admin_menu[$menu_id])) {
            unset($admin_menu[$menu_id]);
            update_option('admin_menu', $admin_menu);
        }
    } else {
        foreach ($menu_id as $key => $m_id) {
            if(isset($admin_menu[$m_id])) {
                unset($admin_menu[$m_id]);
            }
        }
        update_option('admin_menu', $admin_menu);
    }
    return;
}

function register_admin_submenu($args) {
    if (get_option("stop_update_menu") && !DEVMODE) {
        return;
    }
    // acceptable args are: mm_id, id, title, icon, page, class, access, condition
    if(!isset($args['id']))
        return false;
    $admin_submenu = get_option('admin_submenu');
    if(!$admin_submenu) {
        $admin_submenu = array();
    }
    if(isset($admin_submenu[$args['id']])) {
        return;
        $the_menu = $admin_submenu[$args['id']];
        if(isset($args['mm_id'])) {
            $the_submenu['mm_id'] = $args['mm_id'];
        }
        if(isset($args['title'])) {
            $the_submenu['title'] = $args['title'];
        }
        if(isset($args['icon'])) {
            $the_submenu['icon'] = $args['icon'];
        }
        if(isset($args['page'])) {
            $the_submenu['page'] = $args['page'];
        }
        if(isset($args['class'])) {
            $the_submenu['class'] = $args['class'];
        }
        if(isset($args['access'])) {
            $the_submenu['access'] = $args['access'];
        }
        if(isset($args['condition'])) {
            $the_submenu['condition'] = $args['condition'];
        } else $the_submenu['condition'] = true;
        $admin_submenu[$args['id']] = $the_submenu;
        update_option('admin_submenu', $admin_submenu);
    } else {
        $the_submenu = array();
        if(isset($args['id'])) {
            $the_submenu['id'] = $args['id'];
        } else return false;
        if(isset($args['title'])) {
            $the_submenu['title'] = $args['title'];
        } else return false;
        if(isset($args['mm_id'])) {
            $the_submenu['mm_id'] = $args['mm_id'];
        } else return false;
        if(isset($args['icon'])) {
            $the_submenu['icon'] = $args['icon'];
        }
        if(isset($args['page'])) {
            $the_submenu['page'] = $args['page'];
        }
        if(isset($args['class'])) {
            $the_submenu['class'] = $args['class'];
        }
        if(isset($args['access'])) {
            $the_submenu['access'] = $args['access'];
        } else $the_submenu['access'] = 'edit_options';
        if(isset($args['condition'])) {
            $the_submenu['condition'] = $args['condition'];
        } else $the_submenu['condition'] = true;
        $admin_submenu[$args['id']] = $the_submenu;
        update_option('admin_submenu', $admin_submenu);
    }
}

function unregister_admin_submenu($submenu_id) {
    if (get_option("stop_update_menu") && !DEVMODE) {
        return;
    }
    $admin_submenu = get_option('admin_submenu');
    if(!is_array($submenu_id)) {
        if(isset($admin_submenu[$submenu_id])) {
            unset($admin_submenu[$submenu_id]);
            update_option('admin_submenu', $admin_submenu);
        }
    } else {
        foreach ($submenu_id as $key => $sm_id) {
            if(isset($admin_submenu[$sm_id])) {
                unset($admin_submenu[$sm_id]);
            }
        }
        update_option('admin_submenu', $admin_submenu);
    }
    return;
}

function nav_menu($settings = array()) {
    global $app;
    $menu = new menu($app->request_link);
    $menu->display_menu($settings);
    return $menu;
}

/*

SINCE: Version 1
DESC: This function is used to check if an admin menu has sub menu. can be referenced at admin/sidebar.php
ARGS: $menu_id(required) -- The menu id of the main menu to be tested
RETURNS: false if the menu has no sub menu else returns an array of the submenu with the sub menu ids as the keys and settings as the values

*/
function has_child($menu_id) {
    $admin_submenu = get_option('admin_submenu');
    if(!$admin_submenu) {
        return false;
    }
    $result = array();
    foreach ($admin_submenu as $submenu_id => $settings) {
        if(strtolower($settings['mm_id']) == strtolower($menu_id)) {
            $result[$submenu_id] = $settings;
        }
    }
    if(empty($result)) {
        return false;
    } else return $result;
}

function render_page_scripts() {
    ?>
    <div id="evolution-php-javascript-embed"> 
        <script type="text/javascript">
            var scr = document.querySelectorAll(".evolution-php-javascript");
            for(var script in scr) {
                try {
                    var url = scr[script].dataset.url+"?ver=<?php echo VERSION ?>";
                    document.write("<script type=\"text/javascript\" src=\""+url+"\"><\/script>");
                }
                catch(err) {}
                finally{}
            }
        </script> 
    </div>
    
    <script type="text/javascript">
        function ev_php_embed_scripts() {
            var e = document.getElementById("evolution-php-javascript-embed");
            var scr = document.querySelectorAll(".evolution-php-javascript");
            var html = document.createElement("div");
            for(var script in scr) {
                try {
                    var url = scr[script].dataset.url+"?ver=<?php echo VERSION ?>";
                    var s = document.createElement("script");
                    s.setAttribute("src", url);
                    html.appendChild(s);
                }
                catch(err) {

                }
                finally{}
            }
            while (e.firstChild) {
                e.removeChild(e.firstChild);
            }
            setTimeout(function(){
                e.appendChild(html);
            }, 2000);
        }
    </script>
    <!-- <script type="text/javascript" src="app/assets/js/page-scripts/load-scripts.js"></script> -->
    <?php
}

function add_page_stylesheet($url, $stylesheet_id, $is_return = false, $add_version = true) {
    
    global $post_meta;
    if(isset($post_meta['css'][$stylesheet_id])) {
        return;
    }
    $home = "";//($option = get_option("home_url")) ? $option : "";
    $url = $home . apply_filters("add_page_stylesheet_".$stylesheet_id, $url);
    $version = $add_version ? "?ver=".VERSION : "";
    $post_meta['css'][$stylesheet_id] = $url;
    ob_start();
    ?>
    <link rel="stylesheet" type="text/css" href="<?php echo $url.$version ?>">
    <?php
    if(DEVMODE) {
        $file = ABSPATH.'css-reference-register.txt';
        $searchfor = $stylesheet_id."\t-\t".$url;
        // header('Content-Type: text/plain');
        if(!file_exists($file)) {
            file_put_contents($file, "CSS Log File".PHP_EOL);
        }
        $contents = file_get_contents($file);
        $pattern = preg_quote($searchfor, '/');
        $pattern = "/^.*$pattern.*\$/m";
        if(!preg_match_all($pattern, $contents, $matches)){
            $fp = fopen($file, 'a');//opens file in append mode  
            fwrite($fp, $searchfor.PHP_EOL); 
            fclose($fp);
        }
    }
    $template = ob_get_contents();
    ob_get_clean();
    if($is_return) return $template;
    echo $template;
}

function add_page_javascript($url) {
    global $post_meta;
    if(isset($post_meta['js'])) {
        if(in_array($url, $post_meta['js'])) {
            return;
        }
    }
    $home = "";//($option = get_option("home_url")) ? $option : "";
    ?>
    <span class="evolution-php-javascript" data-url="<?php echo $home . $url ?>"></span>
    <?php
    $post_meta['js'][] = $url;
}

function add_datatable_scripts() {
    add_page_javascript("app/assets/plugins/datatables/jquery.dataTables.min.js");
    add_page_javascript("app/assets/plugins/datatables-bs4/js/dataTables.bootstrap4.min.js");
    add_page_javascript("app/assets/plugins/datatables-responsive/js/dataTables.responsive.min.js");
    add_page_javascript("app/assets/plugins/datatables-responsive/js/responsive.bootstrap4.min.js");
    add_page_javascript("app/assets/plugins/datatables-buttons/js/dataTables.buttons.min.js");
    add_page_javascript("app/assets/plugins/datatables-buttons/js/buttons.bootstrap4.min.js");
    add_page_javascript("app/assets/plugins/jszip/jszip.min.js");
    add_page_javascript("app/assets/plugins/pdfmake/pdfmake.min.js");
    add_page_javascript("app/assets/plugins/pdfmake/vfs_fonts.js");
    add_page_javascript("app/assets/plugins/datatables-buttons/js/buttons.html5.min.js");
    add_page_javascript("app/assets/plugins/datatables-buttons/js/buttons.print.min.js");
    add_page_javascript("app/assets/plugins/datatables-buttons/js/buttons.colVis.min.js");
    // add_page_javascript("app/assets/magnific-popup/dist/jquery.magnific-popup.min.js");
}

function is_child_of($request_link) {
    $request_link = strtolower($request_link);
    $admin_submenu = get_option('admin_submenu');
    if(!$admin_submenu) {
        return false;
    }
    foreach ($admin_submenu as $submenu_id => $settings) {
        if($settings['page'] == $request_link) {
            if(has_child($settings['mm_id'])) {
                return $settings['mm_id'];
            }
        }
    }
    return false;
}

function get_age($dob) {
    if($dob == '') {
        return 'NA';
    }
    $current_time = time();
    $dob = strtotime($dob);
    $age = $current_time - $dob;
    if($age < 31536000) {
        $age = floor($age/2635200);
        if($age > 1) {
            return $age.' Months';
        } else return $age.' Month';
    } else {
        $age = floor($age/31536000);
        if($age > 1) {
            return $age.' Years';
        } else return $age.' Year';
    }

}

function get_days_spent($date) {
    $current_time = time();
    $days = $current_time - $date;
    return floor($days/86400) + 1;
}

function time_elapsed_string($datetime, $full = false) {
    $now = new DateTime;
    $ago = new DateTime($datetime);
    $diff = $now->diff($ago);

    $diff->w = floor($diff->d / 7);
    $diff->d -= $diff->w * 7;

    $string = array(
        'y' => 'year',
        'm' => 'month',
        'w' => 'week',
        'd' => 'day',
        'h' => 'hour',
        'i' => 'minute',
        's' => 'second',
    );
    foreach ($string as $k => &$v) {
        if ($diff->$k) {
            $v = $diff->$k . ' ' . $v . ($diff->$k > 1 ? 's' : '');
        } else {
            unset($string[$k]);
        }
    }

    if (!$full) $string = array_slice($string, 0, 1);
    return $string ? implode(', ', $string) . ' ago' : 'just now';
}

function _time_elapsed_string($diff, $full = false) {

    $time_sec = array(
        'y' => 31536000,
        'm' => 2592000,
        'w' => 604800,
        'd' => 86400,
        'h' => 3600,
        'i' => 60,
        's' => 1,
    );

    $string = array(
        'y' => 'year',
        'm' => 'month',
        'w' => 'week',
        'd' => 'day',
        'h' => 'hour',
        'i' => 'minute',
        's' => 'second',
    );
    foreach ($string as $k => &$v) {
        if ($diff > $time_sec[$k]) {
            $t = floor($diff/$time_sec[$k]);
            $v = $t . ' ' . $v . ($t > 1 ? 's' : '');
            $diff = $diff % $time_sec[$k];
        } else {
            unset($string[$k]);
        }
    }

    if (!$full) $string = array_slice($string, 0, 1);
    return $string ? implode(', ', $string) . ' ago' : 'just now';
}

function _time_btw_string($diff, $full = false) {

    $time_sec = array(
        'y' => 31536000,
        'm' => 2592000,
        'w' => 604800,
        'd' => 86400,
        'h' => 3600,
        'i' => 60,
        's' => 1,
    );

    $string = array(
        'y' => 'year',
        'm' => 'month',
        'w' => 'week',
        'd' => 'day',
        'h' => 'hour',
        'i' => 'minute',
        's' => 'second',
    );
    foreach ($string as $k => &$v) {
        if ($diff > $time_sec[$k]) {
            $t = floor($diff/$time_sec[$k]);
            $v = $t . ' ' . $v . ($t > 1 ? 's' : '');
            $diff = $diff % $time_sec[$k];
        } else {
            unset($string[$k]);
        }
    }

    if (!$full) $string = array_slice($string, 0, 1);
    return $string ? implode(', ', $string) : 'just now';
}

function return_method($dest = false) {
    if(!$dest) {
        $dest = $_SERVER['HTTP_REFERER'];
    }
    $dest_arr = explode("/", $dest);
    $v_permalink = end($dest_arr);
    global $app;
    if($v_permalink !== $app->post_meta['permalink']) {
        echo '<script>window.location = "'.$dest.'"</script>';
    } else echo '<script>window.location = "dashboard"</script>';
    
}

function date_limits($params) {
    switch ($params) {
        case 'today':
            $start = strtotime("12AM today");
            $stop = time();
            break;

        case 'yesterday':
            $start = strtotime("12AM yesterday");
            $stop = strtotime("12AM today");
            break;

        case 'this_week':
            $start = strtotime("Monday this week");
            $stop = time();
            break;

        case 'last_week':
            $start = strtotime("Monday last week");
            $stop = strtotime("Monday this week");
            break;

        case 'this_month':
            $start = strtotime("12AM first day of this month");
            $stop = time();
            break;

        case 'last_month':
            $start = strtotime("12AM first day of last month");
            $stop = strtotime("12AM first day of this month");
            break;

        case 'this_year':
            $start = strtotime('first day of January ' . date('Y'));
            $stop = time();
            break;

        case 'last_year':
            $start = strtotime('first day of January ' . (date('Y') - 1));
            $stop = strtotime('first day of January ' . date('Y'));
            break;
        
        default:
            # code...
            break;
    }
    return array('start' => $start, 'stop' => $stop);
}

function date_set_limit($parameter = 'this-year') {
    switch($parameter) {
        case 'this-year':
                $y = date('Y', time());
                return array('start' => strtotime('1 Jan '.$y), 'end' => time());
            break;

        case 'this-month':
                $ym = date('M Y', time());
                return array('start' => strtotime('1 '.$ym), 'end' => time());
            break;

        case 'last-month':
                $ym = date('M Y', time());
                $lm = ((int) date('m', time()) == 1) ? 12 : ((int) date('m', time())) - 1;
                $y = ($lm == 12) ? (int) date('Y', time()) : date('Y', time());
                return array('start' => strtotime($y.'-'.$lm.'-1') , 'end' => strtotime('1 '.$ym));
            break;

        case 'today':
                $d = date('d ', time());
                $ym = date('M Y', time());
                return array('start' => strtotime($d.$ym), 'end' => time());
            break;

        case 'yesterday':
                $d = date('d ', time());
                $ym = date('M Y', time());
                $ysd = ((int) $d) - 1;
                return array('start' => strtotime($ysd.$ym), 'end' => strtotime($d.$ym));
            break;

        case 'this-pz-year':
                if((int) date('m', time()) > 5) {
                    $y = (int) date('Y', time());
                } else {
                    $y = (int) date('Y', time()) - 1;
                }
                return array('start' => strtotime('1 Jun '.$y), 'end' => time());
            break;

        case 'last-pz-year':
                if((int) date('m', time()) > 5) {
                    $ey = (int) date('Y', time());
                    $sy = (int) date('Y', time()) - 1;
                } else {
                    $ey = (int) date('Y', time()) - 1;
                    $sy = (int) date('Y', time()) - 2;
                }
                return array('start' => strtotime('1 Jun '.$sy), 'end' => strtotime('1 Jun '.$ey));
            break;
    }
    
}

function get_select_array_post($query_args) {
    $res = array();
    $post = new post;
    $q = $post->get_post_by_meta_data($query_args);
    if(_count($q) > 0) {
        foreach($q as $qr) {
            $res[$qr['title']] = $qr['id'];
        }
    }
    return $res;
}

//modified version 1.3
function filter_post_result_by_date_range($array, $range_from, $range_to, $param = 'posted_on') {
    if(_count($array) < 1) {
        return array();
    }
    $result = array();
    foreach ($array as $key => $value) {
        if($value[$param] < $range_to && $value[$param] > $range_from) {
            $result[$key] = $value;
        } else continue;
    }
    return $result;
}

function filter_user_result_by_date_range($array, $range_from, $range_to, $param = 'date_created') {
    if(_count($array) < 1) {
        return array();
    }
    $result = array();
    foreach ($array as $key => $value) {
        if($value[$param] < $range_to && $value[$param] > $range_from) {
            $result[$key] = $value;
        } else continue;
    }
    return $result;
}

function toMoney($amount, $unit = "")
{
    if($unit === "") {
        $unit = ($option = get_option("default_currency")) ? $option : "NGN";
    }
    if($amount === "") {
        return "-";
    }
    $unit = $unit == 'N' ? 'NGN' : $unit;
    try {
        $fmt = new NumberFormatter('en_NG', NumberFormatter::CURRENCY);
        return $amount > 0 ? $fmt->formatCurrency($amount, $unit) : "(".$fmt->formatCurrency(($amount * -1), $unit).")";
    }
    catch (Exception $e) {
        
    }
    finally {
        return $amount > 0 ? $unit.number_format($amount, 2) : "(".$unit.number_format(($amount * -1), 2).")";
    }
    
}

function stripfirstdash($input) {
    if(substr( $input, 0, 1 ) === "-" && $input !== "" && $input !== null) {
        return substr($input, 1);
    }
    return $input;
}

function addfirstdash($input) {
    if(substr( $input, 0, 1 ) !== "-" && $input !== "" && $input !== null) {
        return '-'.$input;
    }
    return $input;
}

function file_upload_errors() {
    $phpFileUploadErrors = array(
        0 => 'There is no error, the file uploaded with success',
        1 => 'The uploaded file exceeds the upload_max_filesize directive in php.ini',
        2 => 'The uploaded file exceeds the MAX_FILE_SIZE directive that was specified in the HTML form',
        3 => 'The uploaded file was only partially uploaded',
        4 => 'No file was uploaded',
        6 => 'Missing a temporary folder',
        7 => 'Failed to write file to disk.',
        8 => 'A PHP extension stopped the file upload.',
    );
    return $phpFileUploadErrors;
}

function get_select_options_from_post($args, $key, $val = 'id', $raw = true, $sort = false, $wildcard = false) {
    $result = [];
    if($raw) {
        $post = new post;
        $options = $post->get_post_by_meta_data($args);
        if($sort) {
            $sort = strtoupper($sort);
            $sorting = new sorting;
            switch ($sort) {
                case 'ASC':
                case 'DESC':
                    $options = $sorting->sort_by_meta_value($options, $key, $sort);
                    break;
                
                default:
                    $options = $sorting->sort_by_meta_value($options, $key, "ASC");
                    break;
            }
        }
    } else {
        $options = $args;
    }
    if(_count($options) > 0){
        foreach ($options as $value) {
            if($wildcard) {
                $result[$value[$key]] = "%".$value[$val]."%";
            } else {
                $result[$value[$key]] = $value[$val];
            }
            
        }
    }
    return $result;
}

function get_select_options_from_user($args, $val = 'id', $raw = true, $sort = false) {
    $result = [];
    if($raw) {
        $user = new user;
        $options = $user->get_user_by_meta_data($args);
        if($sort) {
            $sort = strtoupper($sort);
            $sorting = new sorting;
            switch ($sort) {
                case 'ASC':
                case 'DESC':
                    $options = $sorting->sort_by_meta_value($options, 'surname', $sort);
                    break;
                
                default:
                    $options = $sorting->sort_by_meta_value($options, 'surname', "ASC");
                    break;
            }
        }
    } else {
        $options = $args;
    }
    if(_count($options) > 0){
        foreach ($options as $value) {
            $result[get_fullname($value)] = $value[$val];
        }
    }
    return $result;
}

function get_select_options_from_db($table, $args, $key, $val = 'id', $raw = true, $sort = false) {
    $result = [];
    if($raw) {
        $query = new query;
        $sql = "SELECT $key, $val FROM $table";
        if(_count($args) && is_array($args)) {
            $sql .= " WHERE";
            foreach ($args as $k => $v) {
                $sql .= " $k LIKE '$v' AND";
            }
            $sql = substr($sql, 0, -4);
        }

        if($sort) {
            switch ($sort) {
                case 'ASC':
                case 'DESC':
                    $sql .= " ORDER BY $key $sort";
                    break;
                
                default:
                    $sql .= " ORDER BY $key ASC";
                    break;
            }
        }
        $options = $query->get_results($sql, ARRAY_A);
    } else {
        $options = $args;
    }
    if(_count($options) > 0){
        foreach ($options as $value) {
            $result[$value[$key]] = $value[$val];
        }
    }
    return $result;
}

function add_action($action, $cb, $priority = 1) {
    $actions = new actions;
    return $actions->add_action($action, $cb, $priority);
}

function remove_action($action, $cb) {
    $actions = new actions;
    return $actions->drop_action($action, $cb);
}

function drop_action($action, $cb) {
    $actions = new actions;
    return $actions->drop_action($action, $cb);
}

function do_action($action, $args = array(), $return = "echo") {
    $actions = new actions;
    return $actions->do_action($action, $args, $return);
}

function add_filter($filter, $cb, $priority = 1) {
    $obj = new filter;
    return $obj->add_filter($filter, $cb, $priority);
}

function apply_filters($filter, $subject, ...$args) {
    $obj = new filter;
    return $obj->apply_filters($filter, $subject, ...$args);
}

function drop_filter($filter, $cb) {
    $obj = new filter;
    return $obj->drop_filter($filter, $cb);
}

function remove_filter($filter, $cb) {
    $obj = new filter;
    return $obj->drop_filter($filter, $cb);
}

function inform_user($user_id, $info, $subject, $action = false, ...$channels) {
    $support = new support;
    $support->action = $action ? $action : get_option("home_url")."dashboard";
    $support->inform_user($user_id, $info, $subject, ...$channels);
    return $support;
}

function inform_users($users, $info, $subject, $action = false, ...$channels) {
    $support = new support;
    $support->action = $action ? $action : get_option("home_url")."dashboard";
    $support->subject = $subject;
    $support->ready_state();
    $support->set_receivers($users);
    $support->set_content($info);
    $support->send_notice(...$channels);
    return $support;
}

function inform_user_roles($roles, $info, $subject, $action = false, ...$channels) {
    $roles = !is_array($roles) ? array($roles) : $roles;
    $support = new support;
    $support->action = $action ? $action : get_option("home_url")."dashboard";
    $support->subject = $subject;
    $support->ready_state();
    $support->set_by_role(...$roles);
    $support->set_content($info);
    $support->send_notice(...$channels);
    return $support;
}

function inform_admins($info, $subject, $action = false, ...$roles) {
    global $app;
    $support = new support;
    $support->action = $action ? $action : get_option("home_url")."dashboard";
    $support->db_section_id = isset($app->user_meta['db_section_id']) ? $app->user_meta['db_section_id'] : -1;
    $support->inform_admins($info, $subject, ...$roles);
    return $support;
}

function admin_log($narration) {
    $post = new post;
    $args = [
        'type' => 'admin_log',
        'narration' => $narration
    ];
    $post->add_post($args);
}

function get_fullname($user_id, $add_link = false) {
    if(is_array($user_id)) {
        if(current_user_can("edit_others_profile") && $add_link) {
            $fullname = '<a href="profile?id='.$user_id['id'].'" class="popmeup">'.strtoupper($user_id['surname'].' '.$user_id['other_names']).'</a>';
        } else $fullname = strtoupper($user_id['surname'].' '.$user_id['other_names']);
        return apply_filters("get_fullname", $fullname, $user_id, $add_link);
    }
    $user = new user;
    $user_meta = $user->get_user_meta($user_id);
    if(!$user_meta) {
        return false;
    }
    if(current_user_can("edit_others_profile") && $add_link) {
            $fullname = '<a href="profile?id='.$user_meta['id'].'" class="popmeup">'.strtoupper($user_meta['surname'].' '.$user_meta['other_names']).'</a>';
    } else $fullname = strtoupper($user_meta['surname'].' '.$user_meta['other_names']);
    return apply_filters("get_fullname", $fullname, $user_meta, $add_link);
}

function trim_array($input) {
    $res = [];
    if(_count($input) > 0 && $input) {
        foreach ($input as $key => $value) {
            $res[trim($key)] = trim($value);
        }
    }
    return $res;
}

function new_token() {
    $session = Session::getInstance();
    $user = new user;
    $seg1 = time();
    $seg2 = rand(100000, 99999999);
    $seg3 = SALT;
    $seg4 = $session->key;
    $token = md5($seg1.$seg2.$seg3.$seg4).md5($seg3.$seg1.$seg4.$seg2).md5($seg2.$seg4.$seg3.$seg1);
    $res = $user->update_user_meta($session->id, ['securetoken' => $token]);
    return $token;
}

function verify_token($token, $authe_once = false) {
    $session = Session::getInstance();
    $user = new user;
    $user_meta = $user->get_user_meta($session->id);
    $user->update_user_meta($user_meta['id'], ['yep' => 'tek']);
    if($user_meta['securetoken'] !== $token) {
        return false;
    } else {
        if($authe_once) {
            return new_token();
        }
        return $token;
    }
}

function token_error($msg = 'You are accessing this page with an invalid token') {
    echo '<p class="error">'.$msg.'</p>';
}

function upload_base64_image($data, $image_name, $img_path, $files_arr) {
    if($data != '') {
        $final_name = $files_arr[$image_name]["name"];
        $final_name = clean($final_name);

        if(!file_exists($img_path)) {
            mkdir($img_path, 0777, true);
        }
        list($type, $data) = explode(';', $data);
        list(, $data)      = explode(',', $data);
        // return $data;
        $data = base64_decode($data);
        file_put_contents($img_path . $final_name, $data);
        return array(1, $img_path . $final_name);
    } else return array(0, '');
}

function remove_library_file($library_id, $serverfilename = false, $prefix = ABSPATH) {
    $post = new post;
    $library_meta = (is_array($library_id)) ? $library_id : $post->get_post_meta($library_id);
    if(!$library_meta) return false;
    if($serverfilename) {
        $files = _unserialize($library_meta['files']);
        unset($files[$serverfilename]);
        $unlink = file_exists($prefix.$serverfilename) ? unlink($prefix.$serverfilename) : false;
        if($unlink) {
            If(empty($files)) {
                $post->drop_post($library_meta['id']);
            } else {
                $files = serialize($files);
                $post->update_post_meta($library_meta['id'], ['files' => $files]);
            }
            return true;
        } else return false;
    } else {
        $files = _unserialize($library_meta['files']);
        if(_count($files)) {
            foreach ($files as $serverfilename => $file_meta) {
                unlink($prefix.$serverfilename);
            }
        }
        $post->drop_post($library_meta['id']);
        return true;
    }
}


/**
 * use library file ref to delete a library
 * @param  string  $ref     library reference
 * @param  [boolean or int] $user_id Particular user library
 * @return null             null
 */
function remove_library_file_by_ref($ref, $user_id = false) {
    $args = ['type' => 'image_library', 'ref' => $ref];
    if($user_id) {
        $args['user_id'] = $user_id;
    }
    $res = db_post_unique($args);
    if($res) {
        return remove_library_file($res);
    } else return false;
}


function get_upload_library_files( $ref, $user_id = false ) {
    $args = ['type' => 'image_library', 'ref' => $ref];
    if($user_id) {
        $args['user_id'] = $user_id;
    }
    $res = db_post_unique($args);
    if($res) {
        $files = _unserialize($res['files']);
        if(_count($files)) {
            return ['files' => $files, 'raw' => $res];
        } else return false;
    } else return false;
}

function UploadFile($files_arr, $name, $path, $filetypes, $maxlen, $save_as = "")
        {
            $e = [1 => 'File exceeds upload_max_filesize defined in php.ini',
                2 => 'File exceeds MAX_FILE_SIZE directive in HTML form',
                3 => 'File was only partially uploaded',
                4 => 'No file was uploaded',
                6 => 'PHP is missing a temporary folder',
                7 => 'Failed to write file to disk',
                8 => 'File upload stopped by extension'];
            if (!isset($files_arr[$name]['name']))
                return array(-1, 'Upload failed');

            if (!in_array($files_arr[$name]['type'], $filetypes))
                return array(-2, 'Wrong file type');
         
            if ($files_arr[$name]['size'] > $maxlen)
                return array(-3, 'File too large');

            if ($files_arr[$name]['error'] > 0)
                return array($files_arr[$name]['error'], $e[$files_arr[$name]['error']]);

            if (!file_exists($path)) {
                mkdir($path, 0777, true);
            }
            if($save_as != "") {
                $ext_arr = explode(".", $files_arr[$name]['name']);
                $ext = end($ext_arr);
                $files_arr[$name]['name'] = $save_as.".".$ext;
            }
              
           if(move_uploaded_file($files_arr[$name]['tmp_name'],$path.$files_arr[$name]['name'])) {
                return array(0, $path.$files_arr[$name]['name']);
           }
        }

function upload_from_url($url, $dir, $extensions = array('jpg', 'jpeg')) {
    if (!file_exists($dir)) {
        mkdir($dir, 0777, true);
    }
    $file = explode("/", $url);
    $file = end($file);
    $ext = explode(".", $file);
    $ext = end($ext);
    if (!in_array($ext, $extensions))
        return array(-2, 'Wrong file type');

    $res = file_put_contents($dir."/".$file, file_get_contents($url));
    if($res) {
        return array(0, $dir."/".$file, $file, $ext, $dir);
    } else return array(-1, "Unable to get file");
}

function add_file_to_image_library_db($user_id, $ref, $file, $folder, $file_title, $file_type) {
    $post = new post;
    $ds = "/";
    $args = ['user_id' => $user_id, 'ref' => $ref];
    $response = array();
    $file = $folder.$ds.$file;
    $size = filesize(ABSPATH.$file);
    $response['file'] = $file;
    $response['file_title'] = $file_title;
    $response['file_type'] = $file_type;
    $response['error'] = 0;
    $response['ctrlid'] = base64_encode($file);
    $existing = $post->get_post_by_meta_data(['type' => 'image_library', 'ref' => strtolower($args['ref']), 'user_id' => $args['user_id']]);
    if(_count($existing)) {
        $existing = array_shift($existing);
        $files = _unserialize($existing['files']);
        $files[$file] = ['file_name' => $file, 'file_type' => $file_type, 'size' => $size, 'date_added' => time(), 'ctrlid' => $response['ctrlid'], 'title' => $file_title];
        $args['files'] = serialize($files);
        $args['files'] = base64_encode($args['files']);
        $post->update_post_meta($existing['id'], $args);
        $response['id'] = $existing['id'];
    } else {
        $args['ref'] = strtolower($args['ref']);
        $files = array();
        $files[$file] = ['file_name' => $file, 'file_type' => $file_type, 'size' => $size, 'date_added' => time(), 'ctrlid' => $response['ctrlid'], 'title' => $file_title];
        $args['files'] = serialize($files);
        $args['files'] = base64_encode($args['files']);
        $args['type'] = 'image_library';
        $response['id'] = $post->add_post($args);
    }
    return $response;
}

function get_user_image($user_id) {
    $user = new user;
    if(!is_array($user_id)) {
        $user_meta = $user->get_user_meta($user_id);
    } else $user_meta = $user_id;

    if(isset($user_meta['profile_picture'])) {
        return apply_filters("get_user_image", get_option("home_url").$user_meta['profile_picture'], $user_meta);
    } else {
        return apply_filters("get_user_image", get_option("home_url")."app/images/default-user.png", $user_meta);
    }
}

function generate_otp($user_id) {
    $user = new user;
    $pin = rand(100000, 999999);
    $securedpin = SHA1(md5($pin));
    $expiry = time() + (60*15);
    if($user->update_user_meta($user_id, ['otp' => $securedpin, 'otp_expiry' => $expiry])){
        $info = "Your password retrival one time pin is ".$pin.". This pin expires by ".date(_DATE_FORMAT_." H:i:s", $expiry);
        $support = inform_user($user_id, $info, "ONE-TIME PASSWORD", get_option("home_url")."otp?user_id=".$user_id, SMS, EMAIL);
        return $support;
    }
}

function verifyotp($otp, $user_id) {
    $user = new user;
    $usermeta = $user->get_user_meta($user_id);
    if(!$usermeta) return false;
    if(time() > $usermeta['otp_expiry']) {
        $user->update_user_meta($user_id, ['otp' => '', 'otp_expiry' => 0]);
        return false;
    }
    if($usermeta['otp'] == '') {
        return false;
    }
    $otp = SHA1(md5($otp));
    if($otp === $usermeta['otp']) {
        $user->update_user_meta($user_id, ['otp' => '', 'otp_expiry' => 0]);
        return true;
    }
}

function sum_array_values($arr) {
    $sum = 0;
    if(_count($arr)) {
        foreach ($arr as $key => $value) {
            $sum += $value;
        }
    }
    return $sum;
}

function refresh_software() {
    $software = new app;
    $software->refresh();
}

function activate_plugin($args) {
    $res = update_option('_is_active_'.$args['plugin'], 1);
    if($res) {
        refresh_software();
        return ['status' => true, 'msg' => 'Congratulations, plugin was activated successfully.'];
    }  else return ['status' => false, 'msg' => 'Oops, something went wrong. Plugin could not be activated at the moment.'];
    
}

function deactivate_plugin($args) {
    $res = update_option('_is_active_'.$args['plugin'], 0);
    if($res) {
        refresh_software();
        return ['status' => true, 'msg' => 'Congratulations, plugin was deactivated successfully.'];
    }  else return ['status' => false, 'msg' => 'Oops, something went wrong. Plugin could not be deactivated at the moment.'];
}

function switch_result_keys($result) {
    if(_count($result)) {
        foreach ($result as $key => $value) {
            $result[$value['id']] = $value;
            unset($result[$key]);
        }
    }
    return $result;
}

function internationalize_phone_number($phone_number, $country_code = '234') {
    $test = explode(",", $phone_number);
    if(_count($test) > 1) {
        $test = trim_array($test);
        $res = "";
        foreach ($test as $number) {
            $res .= internationalize_phone_number($number, $country_code).",";
        }
        $res = substr($res, 0, -1);
        return $res;
    }
    //Remove any parentheses and the numbers they contain:
    $phone_number = preg_replace("/\([0-9]+?\)/", "", $phone_number);

    //Remove plus signs in country code
    $country_code = str_replace("+", "", $country_code);

    //Strip spaces and non-numeric characters:
    $phone_number = preg_replace("/[^0-9]/", "", $phone_number);

    //Strip out leading zeros:
    $phone_number = ltrim($phone_number, '0');

    if ( !preg_match('/^'.$country_code.'/', $phone_number)  ) {
        $phone_number = $country_code.$phone_number;
    }

    return $phone_number;
}

function is_serialized( $data, $strict = true ) {
    // if it isn't a string, it isn't serialized.
    if ( ! is_string( $data ) ) {
        return false;
    }
    $data = trim( $data );
    if ( 'N;' == $data ) {
        return true;
    }
    if ( strlen( $data ) < 4 ) {
        return false;
    }
    if ( ':' !== $data[1] ) {
        return false;
    }
    if ( $strict ) {
        $lastc = substr( $data, -1 );
        if ( ';' !== $lastc && '}' !== $lastc ) {
            return false;
        }
    } else {
        $semicolon = strpos( $data, ';' );
        $brace     = strpos( $data, '}' );
        // Either ; or } must exist.
        if ( false === $semicolon && false === $brace ) {
            return false;
        }
        // But neither must be in the first X characters.
        if ( false !== $semicolon && $semicolon < 3 ) {
            return false;
        }
        if ( false !== $brace && $brace < 4 ) {
            return false;
        }
    }
    $token = $data[0];
    switch ( $token ) {
        case 's':
            if ( $strict ) {
                if ( '"' !== substr( $data, -2, 1 ) ) {
                    return false;
                }
            } elseif ( false === strpos( $data, '"' ) ) {
                return false;
            }
            // or else fall through
        case 'a':
        case 'O':
            return (bool) preg_match( "/^{$token}:[0-9]+:/s", $data );
        case 'b':
        case 'i':
        case 'd':
            $end = $strict ? '$' : '';
            return (bool) preg_match( "/^{$token}:[0-9.E-]+;$end/", $data );
    }
    return false;
}

function add_db_section($user_meta = array()) {
    $session = Session::getInstance();
    if(empty($user_meta)) {
        $user_meta = get_user_meta($session->id);
    }
    // don't add db section if section database is turned off
    if(!get_option("section_database")) return false;

    $exempt_users = trim_array(get_option("exempt_users"));
    // don't add db section if user is exempted
    if(in_array($user_meta['role'], $exempt_users)) return false;

    // don't add db section if user does not have db section id
    if(!isset($user_meta['db_section_id'])) return false;

    return $user_meta['db_section_id'];
}

function get_db_sections($all = true) {
    $post = new post;
    $section_field = get_option("section_field");
    if(!$section_field or $section_field == "") {
        return array();
    }
    if($all)
        return $post->get_post_by_meta_data(['type' => $section_field]);
    return $post->get_post_by_meta_data(['type' => $section_field, 'status' => 'active']);
}

function get_db_section_name($section_id) {
    $post = new post;
    $section_meta = $post->get_post_meta($section_id);
    return $section_meta['section_name'];
}

function db_section_field_name_is_valid($section_field = false) {
    if(!$section_field) {
        $section_field = get_option("section_field");
    }
    if(!$section_field) return false;
    if($section_field == "") return false;
    return true;
}

// function db_section_name_unique($section_name, $section_field = false) {
//     if(!$section_field) {
//         $section_field = get_option("section_field");
//     }
//     $post = new post;
//     $existing = $post->get_post_by_meta_data(["type" => $section_field, 'section_name' => $section_name]);
//     if(_count($existing)) return false;
//     return true;
// }


function _generate_user_name($args) {
    
    if(isset($args['username'])) return $args['username'];

    if(isset($args['user_name'])) return $args['user_name'];

    if($option = get_option('registration_use_field_for_username')) {
        if(isset($args[$option]) && $args[$option] != '' && $args[$option] != null) {
            return apply_filters("username_filter", $args[$option]);
        }
    }
    $prefix = ($option = get_option('username_prefix')) ? trim($option) : false;
    do {
        $user_name = ($prefix && $prefix !== "") ? $prefix.rand(10000, 99999).rand(10000, 99999) : rand(10000, 99999).rand(10000, 99999).'-'.rand(100, 999);
    } while (!_user_name_is_unique($user_name));
    return apply_filters("username_filter", $user_name);
}

function _user_name_is_unique($user_name) {
    $query = new query;
    $obj = $query->select('users', array('username' => $user_name), 0, 'ASC', 0, 'LIKE');
    $result = $query->query_to_array($obj);
    if(empty($result)) {
        return true;
    } else return false;
}

function get_sign_in_url($selector) {
    // $user = new user;
    return 'dashboard';
    // $admin_roles = unserialize(ADMIN_ROLES);
    // $user_meta = $user->get_user_meta($selector);
    // if(!$user_meta) return 'registration-form/individual.html';
    // if(in_array($user_meta['role'], $admin_roles)) {
    //     // signs these users in directly
    //     return 'dashboard';
    // }
    // if(!isset($user_meta['step1'])) {
    //     return 'registration-form/individual.html';
    // }
    // if(isset($user_meta['step1']) && !isset($user_meta['step2'])) {
    //     return 'registration-form/individual2.html?m='.urlencode($user_meta['username']).'&id='.urlencode($user_meta['id']);
    // }
    // return "logout.php";
}

function clean($string) {
   $string = str_replace(' ', '-', $string); // Replaces all spaces with hyphens.

   return preg_replace('/[^A-Za-z0-9\-.]/', '', $string); // Removes special chars.
}

function db_post_unique($args, $compare = 'LIKE', $use_cache = true) {
    $post = new post;
    $post->use_cache = $use_cache;
    $existing = $post->get_post_by_meta_data($args, $compare);
    if(_count($existing))
        return $existing[0];
    return false;
}

function db_user_unique($args, $compare = 'LIKE', $use_cache = true) {
    $user = new user;
    $user->use_cache = $use_cache;
    $existing = $user->get_user_by_meta_data($args, $compare);
    if(_count($existing))
        return $existing[0];
    return false;
}

function db_item_unique($args, $table) {
    $query = new query;
    $sql = "SELECT * FROM $table WHERE";
    if(_count($args) && is_array($args)) {
        foreach ($args as $k => $v) {
            $sql .= " `$k` LIKE '$v' AND";
        }
        $sql = substr($sql, 0, -4);
        $sql .= " LIMIT 1";
    }
    $res = $query->get_results($sql, ARRAY_A);
    return _count($res) ? array_shift($res) : false;
}

function get_users_by_role($role) {
    $user = new user;
    return $user->get_user_by_meta_data(['role' => $role, 'status' => 'active', 'apply_db_session' => 1]);
}

function display_gender($gender) {
    switch (strtolower($gender)) {
        case 'male':
        case 'm':
        case 'boy':
        case 'man':
        case 'masculine':
        case 'guy':
            return "Male";
            break;

        case 'female':
        case 'f':
        case 'girl':
        case 'woman':
        case 'feminine':
        case 'fmale':
        case 'fm':
            return "Female";
            break;
        
        default:
            return "NA";
            break;
    }
}

function get_library_files($ref, $user_id = -1) {
    $post = new post;
    $response = array("count" => 0, "files" => array(), "library_id" => false);
    $args = ['type' => 'image_library', 'ref' => $ref];
    if($user_id != -1) {
        $args['user_id'] = $user_id;
    }
    $existing = $post->get_post_by_meta_data($args);
    if(_count($existing)) {
        $response['library_id'] = $existing[0]['id'];
        $response['files'] = _unserialize($existing[0]['files']);
        $response['count'] = _count($response['files']);
    }
    return $response;
}

function get_gender_pronouns($user_id) {
    if(!is_array($user_id)) {
        $user = new user;
        $user_id = $user->get_user_meta($user_id);
    }
    $gender = display_gender($user_id['gender'] ?? 'Male');
    switch ($gender) {
        case 'Male':
            return ["he", "his", "him", "He", "His", "Him"];
            break;

        case 'Female':
            return ["she", "her", "her", "She", "Her", "Her"];
            break;
        
        default:
            return ["he/she", "his/her", "him/her", "He/She", "His/Her", "Him/Her"];
            break;
    }
}

function theme_install($args = false) {
    return;
    $theme_name = $args ? $args['option_value'] : false;
    // var_dump($args); die();
    require_once(ABSPATH."contents/themes/theme.php");
    $app = new app;
    $theme = new theme($app);
    $theme->install($theme_name);
}

function update_page_settings($permalink, $settings) {
    $post = new post;
    $post_id = $post->search_post_by_permalink($permalink);
    return $post->update_post_meta($post_id, $settings);
}

function qf_get_limit($options) {
    return $options['size'].", ".$options['size']+$options['query_size'];
}

/**
* Converts bytes into human readable file size.
*
* @param string $bytes
* @return string human readable file size (2,87 Мб)
* @author Mogilev Arseny
*/
function FileSizeConvert($bytes)
{
    $bytes = floatval($bytes);
        $arBytes = array(
            0 => array(
                "UNIT" => "TB",
                "VALUE" => pow(1024, 4)
            ),
            1 => array(
                "UNIT" => "GB",
                "VALUE" => pow(1024, 3)
            ),
            2 => array(
                "UNIT" => "MB",
                "VALUE" => pow(1024, 2)
            ),
            3 => array(
                "UNIT" => "KB",
                "VALUE" => 1024
            ),
            4 => array(
                "UNIT" => "B",
                "VALUE" => 1
            ),
        );

    foreach($arBytes as $arItem)
    {
        if($bytes >= $arItem["VALUE"])
        {
            $result = $bytes / $arItem["VALUE"];
            $result = strval(round($result, 2))." ".$arItem["UNIT"];
            break;
        }
    }
    return $result;
}

function cal_days_in_year($year) {
    $days=0; 
    for($month=1;$month<=12;$month++){ 
        $days = $days + cal_days_in_month(CAL_GREGORIAN,$month,$year);
     }
    return $days;
}

function remaining_days_of_the_year($year, $time = false) {
    $time = $time ? $time : time();
    $d = date("d", $time); //active day
    $m = date("m", $time); //active month
    $y = date("Y", $time); //active year
    if($y < $year) {
        return cal_days_in_year($year);
    }
    else if ($y > $year) {
        return 0;
    }
    else {
        $days=0; 
        for($month=$m;$month<=12;$month++){ 
            $dim = cal_days_in_month(CAL_GREGORIAN,$month,$year);
            $days = ($m === $month) ? $days + ($dim - $d) : $days + $dim;
         }
        return $days;
    }
    
}

function extractKeyWords($string) {
    mb_internal_encoding('UTF-8');
    $stopwords = array('i','a','about','an','and','are','as','at','be','by','com','de','en','for','from','how','in','is','it','la','of','on','or','that','the','this','to','was','what','when','where','who','will','with','und','the','www');
    $string = preg_replace('/[\pP]/u', '', trim(preg_replace('/\s\s+/iu', '', mb_strtolower($string))));
    $matchWords = array_filter(explode(' ',$string) , function ($item) use ($stopwords) { return !($item == '' || in_array($item, $stopwords) || mb_strlen($item) <= 2 || is_numeric($item));});
    $wordCountArr = array_count_values($matchWords);
    arsort($wordCountArr);
    return array_keys(array_slice($wordCountArr, 0, 10));
}

function mbstring_binary_safe_encoding( $reset = false ) {
    static $encodings  = array();
    static $overloaded = null;
 
    if ( is_null( $overloaded ) ) {
        $overloaded = function_exists( 'mb_internal_encoding' ) && ( ini_get( 'mbstring.func_overload' ) & 2 );
    }
 
    if ( false === $overloaded ) {
        return;
    }
 
    if ( ! $reset ) {
        $encoding = mb_internal_encoding();
        array_push( $encodings, $encoding );
        mb_internal_encoding( 'ISO-8859-1' );
    }
 
    if ( $reset && $encodings ) {
        $encoding = array_pop( $encodings );
        mb_internal_encoding( $encoding );
    }
}

function reset_mbstring_encoding() {
    mbstring_binary_safe_encoding( true );
}

function mime2ext($mime) {
    $mime_map = [
        'video/3gpp2'                                                               => '3g2',
        'video/3gp'                                                                 => '3gp',
        'video/3gpp'                                                                => '3gp',
        'application/x-compressed'                                                  => '7zip',
        'audio/x-acc'                                                               => 'aac',
        'audio/ac3'                                                                 => 'ac3',
        'application/postscript'                                                    => 'ai',
        'audio/x-aiff'                                                              => 'aif',
        'audio/aiff'                                                                => 'aif',
        'audio/x-au'                                                                => 'au',
        'video/x-msvideo'                                                           => 'avi',
        'video/msvideo'                                                             => 'avi',
        'video/avi'                                                                 => 'avi',
        'application/x-troff-msvideo'                                               => 'avi',
        'application/macbinary'                                                     => 'bin',
        'application/mac-binary'                                                    => 'bin',
        'application/x-binary'                                                      => 'bin',
        'application/x-macbinary'                                                   => 'bin',
        'image/*'                                                                   => 'all image format',
        'image/bmp'                                                                 => 'bmp',
        'image/x-bmp'                                                               => 'bmp',
        'image/x-bitmap'                                                            => 'bmp',
        'image/x-xbitmap'                                                           => 'bmp',
        'image/x-win-bitmap'                                                        => 'bmp',
        'image/x-windows-bmp'                                                       => 'bmp',
        'image/ms-bmp'                                                              => 'bmp',
        'image/x-ms-bmp'                                                            => 'bmp',
        'application/bmp'                                                           => 'bmp',
        'application/x-bmp'                                                         => 'bmp',
        'application/x-win-bitmap'                                                  => 'bmp',
        'application/cdr'                                                           => 'cdr',
        'application/coreldraw'                                                     => 'cdr',
        'application/x-cdr'                                                         => 'cdr',
        'application/x-coreldraw'                                                   => 'cdr',
        'image/cdr'                                                                 => 'cdr',
        'image/x-cdr'                                                               => 'cdr',
        'zz-application/zz-winassoc-cdr'                                            => 'cdr',
        'application/mac-compactpro'                                                => 'cpt',
        'application/pkix-crl'                                                      => 'crl',
        'application/pkcs-crl'                                                      => 'crl',
        'application/x-x509-ca-cert'                                                => 'crt',
        'application/pkix-cert'                                                     => 'crt',
        'text/css'                                                                  => 'css',
        'text/x-comma-separated-values'                                             => 'csv',
        'text/comma-separated-values'                                               => 'csv',
        'application/vnd.msexcel'                                                   => 'csv',
        'application/x-director'                                                    => 'dcr',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'   => 'docx',
        'application/x-dvi'                                                         => 'dvi',
        'message/rfc822'                                                            => 'eml',
        'application/x-msdownload'                                                  => 'exe',
        'video/x-f4v'                                                               => 'f4v',
        'audio/x-flac'                                                              => 'flac',
        'video/x-flv'                                                               => 'flv',
        'image/gif'                                                                 => 'gif',
        'application/gpg-keys'                                                      => 'gpg',
        'application/x-gtar'                                                        => 'gtar',
        'application/x-gzip'                                                        => 'gzip',
        'application/mac-binhex40'                                                  => 'hqx',
        'application/mac-binhex'                                                    => 'hqx',
        'application/x-binhex40'                                                    => 'hqx',
        'application/x-mac-binhex40'                                                => 'hqx',
        'text/html'                                                                 => 'html',
        'image/x-icon'                                                              => 'ico',
        'image/x-ico'                                                               => 'ico',
        'image/vnd.microsoft.icon'                                                  => 'ico',
        'text/calendar'                                                             => 'ics',
        'application/java-archive'                                                  => 'jar',
        'application/x-java-application'                                            => 'jar',
        'application/x-jar'                                                         => 'jar',
        'image/jp2'                                                                 => 'jp2',
        'video/mj2'                                                                 => 'jp2',
        'image/jpx'                                                                 => 'jp2',
        'image/jpm'                                                                 => 'jp2',
        'image/jpeg'                                                                => 'jpeg',
        'image/pjpeg'                                                               => 'jpeg',
        'application/x-javascript'                                                  => 'js',
        'application/json'                                                          => 'json',
        'text/json'                                                                 => 'json',
        'application/vnd.google-earth.kml+xml'                                      => 'kml',
        'application/vnd.google-earth.kmz'                                          => 'kmz',
        'text/x-log'                                                                => 'log',
        'audio/x-m4a'                                                               => 'm4a',
        'audio/mp4'                                                                 => 'm4a',
        'application/vnd.mpegurl'                                                   => 'm4u',
        'audio/midi'                                                                => 'mid',
        'application/vnd.mif'                                                       => 'mif',
        'video/quicktime'                                                           => 'mov',
        'video/x-sgi-movie'                                                         => 'movie',
        'audio/mpeg'                                                                => 'mp3',
        'audio/mpg'                                                                 => 'mp3',
        'audio/mpeg3'                                                               => 'mp3',
        'audio/mp3'                                                                 => 'mp3',
        'video/mp4'                                                                 => 'mp4',
        'video/mpeg'                                                                => 'mpeg',
        'application/oda'                                                           => 'oda',
        'audio/ogg'                                                                 => 'ogg',
        'video/ogg'                                                                 => 'ogg',
        'application/ogg'                                                           => 'ogg',
        'font/otf'                                                                  => 'otf',
        'application/x-pkcs10'                                                      => 'p10',
        'application/pkcs10'                                                        => 'p10',
        'application/x-pkcs12'                                                      => 'p12',
        'application/x-pkcs7-signature'                                             => 'p7a',
        'application/pkcs7-mime'                                                    => 'p7c',
        'application/x-pkcs7-mime'                                                  => 'p7c',
        'application/x-pkcs7-certreqresp'                                           => 'p7r',
        'application/pkcs7-signature'                                               => 'p7s',
        'application/pdf'                                                           => 'pdf',
        'application/octet-stream'                                                  => 'pdf',
        'application/x-x509-user-cert'                                              => 'pem',
        'application/x-pem-file'                                                    => 'pem',
        'application/pgp'                                                           => 'pgp',
        'application/x-httpd-php'                                                   => 'php',
        'application/php'                                                           => 'php',
        'application/x-php'                                                         => 'php',
        'text/php'                                                                  => 'php',
        'text/x-php'                                                                => 'php',
        'application/x-httpd-php-source'                                            => 'php',
        'image/png'                                                                 => 'png',
        'image/x-png'                                                               => 'png',
        'application/powerpoint'                                                    => 'ppt',
        'application/vnd.ms-powerpoint'                                             => 'ppt',
        'application/vnd.ms-office'                                                 => 'ppt',
        'application/msword'                                                        => 'ppt',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation' => 'pptx',
        'application/x-photoshop'                                                   => 'psd',
        'image/vnd.adobe.photoshop'                                                 => 'psd',
        'audio/x-realaudio'                                                         => 'ra',
        'audio/x-pn-realaudio'                                                      => 'ram',
        'application/x-rar'                                                         => 'rar',
        'application/rar'                                                           => 'rar',
        'application/x-rar-compressed'                                              => 'rar',
        'audio/x-pn-realaudio-plugin'                                               => 'rpm',
        'application/x-pkcs7'                                                       => 'rsa',
        'text/rtf'                                                                  => 'rtf',
        'text/richtext'                                                             => 'rtx',
        'video/vnd.rn-realvideo'                                                    => 'rv',
        'application/x-stuffit'                                                     => 'sit',
        'application/smil'                                                          => 'smil',
        'text/srt'                                                                  => 'srt',
        'image/svg+xml'                                                             => 'svg',
        'application/x-shockwave-flash'                                             => 'swf',
        'application/x-tar'                                                         => 'tar',
        'application/x-gzip-compressed'                                             => 'tgz',
        'image/tiff'                                                                => 'tiff',
        'font/ttf'                                                                  => 'ttf',
        'text/plain'                                                                => 'txt',
        'text/x-vcard'                                                              => 'vcf',
        'application/videolan'                                                      => 'vlc',
        'text/vtt'                                                                  => 'vtt',
        'audio/x-wav'                                                               => 'wav',
        'audio/wave'                                                                => 'wav',
        'audio/wav'                                                                 => 'wav',
        'application/wbxml'                                                         => 'wbxml',
        'video/webm'                                                                => 'webm',
        'image/webp'                                                                => 'webp',
        'audio/x-ms-wma'                                                            => 'wma',
        'application/wmlc'                                                          => 'wmlc',
        'video/x-ms-wmv'                                                            => 'wmv',
        'video/x-ms-asf'                                                            => 'wmv',
        'font/woff'                                                                 => 'woff',
        'font/woff2'                                                                => 'woff2',
        'application/xhtml+xml'                                                     => 'xhtml',
        'application/excel'                                                         => 'xl',
        'application/msexcel'                                                       => 'xls',
        'application/x-msexcel'                                                     => 'xls',
        'application/x-ms-excel'                                                    => 'xls',
        'application/x-excel'                                                       => 'xls',
        'application/x-dos_ms_excel'                                                => 'xls',
        'application/xls'                                                           => 'xls',
        'application/x-xls'                                                         => 'xls',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'         => 'xlsx',
        'application/vnd.ms-excel'                                                  => 'xlsx',
        'application/xml'                                                           => 'xml',
        'text/xml'                                                                  => 'xml',
        'text/xsl'                                                                  => 'xsl',
        'application/xspf+xml'                                                      => 'xspf',
        'application/x-compress'                                                    => 'z',
        'application/x-zip'                                                         => 'zip',
        'application/zip'                                                           => 'zip',
        'application/x-zip-compressed'                                              => 'zip',
        'application/s-compressed'                                                  => 'zip',
        'multipart/x-zip'                                                           => 'zip',
        'text/x-scriptzsh'                                                          => 'zsh',
        'application/acad'                                                          => 'dwg',
        'application/dxf'                                                           => 'dxf',
        'application/drafting'                                                      => 'drw',
        'application/clariscad'                                                     => 'ccad',
        'application/x-planperfect'                                                 => 'pln',
        'application-x/hyperresearch'                                               => 'rwt',
        'application/x-3ds'                                                         => '3ds',
        'image/x-3ds'                                                               => '3ds',
        'model/obj'                                                                 => 'obj'
    ];

    return isset($mime_map[$mime]) ? $mime_map[$mime] : $mime;
}

function mime_str_to_ext($mime_str) {
    $mime_arr = explode(",", $mime_str);
    if(_count($mime_arr) && is_array($mime_arr)) {
        $mime_arr = trim_array($mime_arr);
        $mime_str = "";
        $added = [];
        foreach ($mime_arr as $mime) {
            if(!in_array(mime2ext($mime), $added)) {
                $mime_str .= mime2ext($mime).", ";
                $added[] = mime2ext($mime);
            }
        }
        return substr($mime_str, 0, -2);
    } else return $mime_str;
}

function emptyDir($dirPath) {
    if (! is_dir($dirPath)) {
        return;
        // throw new InvalidArgumentException("$dirPath must be a directory");
    }
    if (substr($dirPath, strlen($dirPath) - 1, 1) != '/') {
        $dirPath .= '/';
    }
    $files = glob($dirPath . '*', GLOB_MARK);
    foreach ($files as $file) {
        if (is_dir($file)) {
            emptyDir($file);
        } else {
            unlink($file);
        }
    }
}

function deleteDir($dirPath) {
    if (! is_dir($dirPath)) {
        return;
        // throw new InvalidArgumentException("$dirPath must be a directory");
    }
    if (substr($dirPath, strlen($dirPath) - 1, 1) != '/') {
        $dirPath .= '/';
    }
    $files = glob($dirPath . '*', GLOB_MARK);
    foreach ($files as $file) {
        if (is_dir($file)) {
            deleteDir($file);
        } else {
            unlink($file);
        }
    }
    sleep(5);
    rmdir($dirPath);
}

function isValidTimeStamp($timestamp)
{
    return ((string) (int) $timestamp === $timestamp) 
        && ($timestamp <= PHP_INT_MAX)
        && ($timestamp >= ~PHP_INT_MAX);
}

function varOperatorConditional($x, $y, $condition = "==") {
    $var_operator = new var_operator;
    return $var_operator->conditional($x, $y, $condition);
}

function varOperatorPlus(...$x) {
    $var_operator = new var_operator;
    return $var_operator->plus(...$x);
}

function varOperatorMinus(...$x) {
    $var_operator = new var_operator;
    return $var_operator->minus(...$x);
}

function varOperatorMul(...$x) {
    $var_operator = new var_operator;
    return $var_operator->mul(...$x);
}

function get_upload_ref($tag) {
    $session = Session::getInstance();
    $record_ref = "uploadref-".$session->id."-".$tag;
    $ref = ($record = get_record($record_ref)) ? $record : "ref-".$tag."-".time();
    update_record($record_ref, $ref);
    return $ref;
}

function generate_upload_ref($tag) {
    $session = Session::getInstance();
    $record_ref = "uploadref-".$session->id."-".$tag;
    $ref = "ref-".$tag."-".time();
    update_record($record_ref, $ref);
    return $ref;
}

function koweb_regex_character_forms($string) {
    $alpha = [
        'a' => 'aA',
        'b' => 'bB',
        'c' => 'cC',
        'd' => 'dD',
        'e' => 'eE',
        'f' => 'fF',
        'g' => 'gG',
        'h' => 'hH',
        'i' => 'iIl1',
        'j' => 'jJ',
        'k' => 'kK',
        'l' => 'lL',
        'm' => 'mM',
        'n' => 'nN',
        'o' => 'oO0',
        'p' => 'pP',
        'q' => 'qQ',
        'r' => 'rR',
        's' => 'sS',
        't' => 'tT',
        'u' => 'uUvV',
        'v' => 'uUvV',
        'w' => 'wW',
        'x' => 'xX',
        'y' => 'yY',
        'z' => 'zZ'
    ];
    $output = "";
    $string = strtolower($string);
    $string = trim($string);
    $str_arr = str_split($string);
    if(!is_array($str_arr)) return $output;
    if(!_count($str_arr)) return $output;
    foreach ($str_arr as $char) {
        if(isset($alpha[$char])) {
            $output .= "[".$alpha[$char]."]";
        } else {
            $output .= "[".$char."]";
        }
    }
    return $output;
}

function build_number_validation_regex() {
    if(get_option("number_text_regex")) return;
    $number_texts = file_get_contents(ABSPATH."app/assets/number-text.json");
    try {
        $output = "(";
        $number_texts = json_decode($number_texts);
        foreach ($number_texts as $key => $string) {
            $output .= koweb_regex_character_forms($string)."|";
        }
        $output = substr($output, 0, -1);
        $output .= ")";
        $output = "^.*" . $output . "\W{0,3}\w{0,3}" . $output . "\W{0,3}\w{0,3}" . $output . ".*$";
        update_option("number_text_regex", $output);
    }
    catch(Exception $e) {
        var_dump($e);
    }
}

function get_first_name($user_meta, $seperator = " ") {
    return explode($seperator, $user_meta['other_names'])[0];
}

function findSerializeError($data1) {
    echo "<pre>";
    $data2 = preg_replace ( '!s:(\d+):"(.*?)";!', "'s:'.strlen('$2').':\"$2\";'",$data1 );
    $max = (strlen ( $data1 ) > strlen ( $data2 )) ? strlen ( $data1 ) : strlen ( $data2 );

    echo $data1 . PHP_EOL;
    echo $data2 . PHP_EOL;

    for($i = 0; $i < $max; $i ++) {

        if (@$data1[$i] !== @$data2[$i]) {

            echo "Diffrence ", @$data1 [$i], " != ", @$data2 [$i], PHP_EOL;
            echo "\t-> ORD number ", ord ( @$data1 [$i] ), " != ", ord ( @$data2 [$i] ), PHP_EOL;
            echo "\t-> Line Number = $i" . PHP_EOL;

            $start = ($i - 20);
            $start = ($start < 0) ? 0 : $start;
            $length = 40;

            $point = $max - $i;
            if ($point < 20) {
                $rlength = 1;
                $rpoint = - $point;
            } else {
                $rpoint = $length - 20;
                $rlength = 1;
            }

            echo "\t-> Section Data1  = ", substr_replace ( substr ( $data1, $start, $length ), "<b style=\"color:green\">{$data1 [$i]}</b>", $rpoint, $rlength ), PHP_EOL;
            echo "\t-> Section Data2  = ", substr_replace ( substr ( $data2, $start, $length ), "<b style=\"color:red\">{$data2 [$i]}</b>", $rpoint, $rlength ), PHP_EOL;
        }

    }

}

function process_croppie_upload(&$args, $image_name, $files, $folder = false, &$response = array()) {
    $picture = $args['imagebase64-'.$image_name];
    unset($args[$image_name]);
    unset($args['imagebase64-'.$image_name]);
    if($files[$image_name]["name"] == "") return $args;
    if(!$folder) {
        $session = Session::getInstance();
        $folder = $session->id."/unsorted/";
    }
    $path = ABSPATH.UPLOADFOLDER.'/'.$folder;
    if($picture != '') {
        $res = upload_base64_image($picture, $image_name, $path, $files);
        $response['res'] = $res;
        if($res[0] == 1) {
            $args[$image_name] = str_replace(ABSPATH, '', $res[1]);
        } else {
            $response['error_msg'] = "image not uploaded";
        }
    }
    return $args;
}

function default_search_template($search_result) {
    $html = "";
    $html .= "<div class=\"row\"><div class=\"col-md-6\"><table class=\"table\"><thead><tr><th>Meta</th><th>Value</th></tr></thead><tbody>";
    foreach ($search_result as $key => $value):
        $html .= "<tr><td class=\"pt-0 pb-0\">";
        $html .= $key;
        $html .= "</td><td class=\"pt-0 pb-0\">";
        $html .= $value;
        $html .= "</td></tr>";
    endforeach;
    $html .= "</tbody></table></div></div>";
    return $html;
}

function search_result_load_more($args) {
    $response = array("html" => "");
    $args = base64_decode($args);
    $args = _unserialize($args);
    $session = Session::getInstance();
    $search = new search($args['table']);
    $search->search_in = $args['search_in'];
    $search->limit = $args['limit'];
    if(isset($args['where'])) {
        $search->where = $args['where'];
    }
    if(isset($args['compare'])) {
        $search->compare = $args['compare'];
    }
    if(isset($args['order_by'])) {
        $search->order_by = $args['order_by'];
    }
    if(isset($args['order'])) {
        $search->order = $args['order'];
    }
    $search->offset = $session->lastsearchresultstop;
    $search_results = $search->get_results($args['search_term']);
    if(!_count($search_results)) {
        $response['html'] = "No result found...";
        $response['continue'] = false;
        return $response;
    }
    if(!is_array($search_results)) {
        $response['html'] = "No result found...";
        $response['continue'] = false;
        return $response;
    }
    foreach ($search_results as $search_result) {
        $response['html'] .= $args['template']($search_result);
    }
    $response['continue'] = true;
    return $response;
}

function on_local_computer() {
    return ($_SERVER['SERVER_ADDR'] === "::1") ? true : false;
}

function _unserialize($items) {
    if(!is_serialized($items)) {
        $items = base64_decode($items);
    }
    return is_serialized($items) ? unserialize($items) : array();
}

function get_ip_info($ip) {
    return file_get_contents("http://ipinfo.io/{$ip}/");
}

function get_my_ip() {
    return file_get_contents("http://ipinfo.io/ip/");
}

function get_my_country() {
    return file_get_contents("http://ipinfo.io/country");
}

function generate_site_binding_id() {
    $site_binding = new site_binding;
    return $site_binding->generate_site_binding_id();
}

function delete_binding($me, $ok) {
    return $me.$ok;
}



// I : send the file inline to the browser (default). The plug-in is used if available. The name given by name is used when one selects the "Save as" option on the link generating the PDF.
// D : send to the browser and force a file download with the name given by name.
// F : save to a local server file with the name given by name.
// S : return the document as a string (name is ignored).
// FI : equivalent to F + I option
// FD : equivalent to F + D option
// E : return the document as base64 mime multi-part email attachment (RFC 2045)
function _make_pdf($settings = array()) {
    $company_name = get_option("company_name");
    global $app;
    $default = [
        "html" => "",
        'k_blank_image' => '_blank.png',
        'pdf_page_format' => 'A4',
        'pdf_page_orientation' => 'P',
        'pdf_creator' => $company_name,
        'pdf_author' => $company_name,
        'pdf_header_title' => $app->post_meta['title'],
        'pdf_subject' => $app->post_meta['title'],
        'pdf_header_string' => $company_name." - ".get_option("company_website"),
        'pdf_unit' => 'mm',
        'pdf_margin_header' => 5,
        'pdf_margin_footer' => 10,
        'pdf_margin_top' => 27,
        'pdf_margin_bottom' => 25,
        'pdf_margin_left' => 15,
        'pdf_margin_right' => 15,
        'pdf_font_name_main' => 'helvetica',
        'pdf_font_size_main' => 10,
        'pdf_font_name_data' => 'helvetica',
        'pdf_font_size_data' => 8,
        'pdf_font_monospaced' => 'courier',
        'pdf_image_scale_ratio' => 1.25,
        'pdf_keywords' => 'TCPDF, PDF, example, test, guide',
        'head_magnification' => 1.1,
        'k_cell_height_ratio' => 1.25,
        'k_title_magnification' => 1.3,
        'k_small_ratio' => '2/3',
        'k_thai_topchars' => true,
        'k_tcpdf_calls_in_html' => false,
        'k_tcpdf_throw_exception_error' => false,
        'k_timezone' => 'UTC',
        'output_file_name' => 'file.pdf',
        'output_type' => 'I',
        'path' => '',
        'pdf_header_logo' => get_option("company-logo"),
        'pdf_header_logo_width' => 30
    ];
    $settings = array_merge($default, $settings);

    require_once(ABSPATH.'app/lib/tcpdf/examples/tcpdf_include.php');

    // create new PDF document
    $pdf = new TCPDF($settings["pdf_page_orientation"], $settings["pdf_unit"], $settings["pdf_page_format"], true, 'UTF-8', false);

    // set document information
    $pdf->SetCreator($settings["pdf_creator"]);
    $pdf->SetAuthor($settings["pdf_author"]);
    $pdf->SetTitle($settings["pdf_header_title"]);
    $pdf->SetSubject($settings["pdf_subject"]);
    $pdf->SetKeywords($settings["pdf_keywords"]);

    // set default header data
    $pdf->SetHeaderData($settings['pdf_header_logo'], $settings['pdf_header_logo_width'], $settings['pdf_header_title'], $settings['pdf_header_string'], array(0,64,255), array(0,64,128));
    $pdf->setFooterData(array(0,64,0), array(0,64,128));

    // set header and footer fonts
    $pdf->setHeaderFont(Array($settings['pdf_font_name_main'], '', $settings['pdf_font_size_main']));
    $pdf->setFooterFont(Array($settings['pdf_font_name_data'], '', $settings['pdf_font_size_data']));

    // set default monospaced font
    $pdf->SetDefaultMonospacedFont($settings['pdf_font_monospaced']);

    // set margins
    $pdf->SetMargins($settings['pdf_margin_left'], $settings['pdf_margin_top'], $settings['pdf_margin_right']);
    $pdf->SetHeaderMargin($settings['pdf_margin_header']);
    $pdf->SetFooterMargin($settings['pdf_margin_footer']);

    // set auto page breaks
    $pdf->SetAutoPageBreak(TRUE, $settings['pdf_margin_bottom']);

    // set image scale factor
    $pdf->setImageScale($settings['pdf_image_scale_ratio']);

    // set some language-dependent strings (optional)
    if (@file_exists(ABSPATH.'app/lib/tcpdf/examples/lang/eng.php')) {
        require_once(ABSPATH.'app/lib/tcpdf/examples/lang/eng.php');
        $pdf->setLanguageArray($l);
    }

    // ---------------------------------------------------------

    // set default font subsetting mode
    $pdf->setFontSubsetting(true);

    // Set font
    // dejavusans is a UTF-8 Unicode font, if you only need to
    // print standard ASCII chars, you can use core fonts like
    // helvetica or times to reduce file size.
    $pdf->SetFont('dejavusans', '', 14, '', true);

    // Add a page
    // This method has several options, check the source code documentation for more information.
    $pdf->AddPage();

    // set text shadow effect
    // $pdf->setTextShadow(array('enabled'=>true, 'depth_w'=>0.2, 'depth_h'=>0.2, 'color'=>array(196,196,196), 'opacity'=>1, 'blend_mode'=>'Normal'));

    // Print text using writeHTMLCell()
    // $pdf->writeHTMLCell(0, 0, '', '', $settings['html'], 0, 1, 0, true, '', true);
    $pdf->writeHTML($settings['html'], true, false, true, false, '');

    // ---------------------------------------------------------
    ob_clean();
    if($settings['path'] !== "") {
        if (!file_exists($settings['path'])) {
            mkdir($settings['path'], 0777, true);
        }
    }
    // Close and output PDF document
    // This method has several options, check the source code documentation for more information.
    return $pdf->Output($settings['path'].$settings['output_file_name'], $settings['output_type']);

    //============================================================+
    // END OF FILE
    //============================================================+
}

function make_pdf($settings = array(), $stream = true, $save = false) {
    $company_name = get_option("company_name");
    global $app;
    $default = [
        "html" => "",
        'output_file_name' => 'file.pdf',
        'output_type' => 'I',
        'path' => '',
        'pdf_header_logo' => get_option("company-logo"),
        'pdf_header_logo_width' => 30
    ];
    $settings = array_merge($default, $settings);

    require_once ABSPATH."app/lib/dompdf/vendor/autoload.php";
     
    // instantiate and use the dompdf class
    $dompdf = new Dompdf();

    $dompdf->loadHtml($settings['html']);
 
    // (Optional) Setup the paper size and orientation
    $dompdf->setPaper('A4', 'portrait');
      
    // Render the HTML as PDF
    $dompdf->render();
    
    if($save) {
        $output = $dompdf->output();
        file_put_contents($settings['path'].$settings['output_file_name'], $output);
    }

    if($stream) {
        // Output the generated PDF to Browser
        $dompdf->stream($settings['output_file_name']);
    }
}

function addOrdinalNumberSuffix($num) {
    try {
        $locale = 'en_US';
        $nf = new NumberFormatter($locale, NumberFormatter::ORDINAL);
        return $nf->format($num);
    }
    catch (Exception $e) {

    }
    finally {
        return ordinal_suffix_of($num);
    } 
  }

function _count($arr) {
    return is_array($arr) ? count($arr) : 0;
}

function ordinal_suffix_of($i) {
    $j = $i % 10;
    $k = $i % 100;
    if ($j == 1 && $k != 11) {
        return $i . "st";
    }
    if ($j == 2 && $k != 12) {
        return $i . "nd";
    }
    if ($j == 3 && $k != 13) {
        return $i . "rd";
    }
    return $i . "th";
}

function process_edit_post_in($meta) {
    foreach($meta as $key => &$value) {
        switch ($key) {
            case 'from':
            case 'to':
                $value = date("m/d/Y", $value);
                break;
            
            default:
                // code...
                break;
        }
    }
    return $meta;
}