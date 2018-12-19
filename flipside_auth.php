<?php
/**
 * Plugin Name: Flipside Auth Plugin
 * Plugin URI: https://dev.burningflipside.com
 * Description: Flipside Auth.
 * Version: 0.2
 * Author: Patrick
 */

function get_base_uri()
{
    $ret = getenv('PROFILES_URL');
    if($ret === false)
    {
        return 'https://profiles.burningflipside.com';
    }
    return $ret;
}

function flipside_redirect_login_page()
{
    if(strpos($_SERVER['REQUEST_URI'], 'wp-login.php'))
    {
        if(isset($_GET['action']) && $_GET['action'] == 'logout')
        {
            wp_logout();
            wp_redirect(get_base_uri().'/logout.php');
            exit();
        }
        $redirect = site_url();
        if(isset($_GET['redirect_to']))
        {
            $redirect = $_GET['redirect_to'];
        }
        wp_redirect(get_base_uri().'/login.php?return='.$redirect);
        exit();
    }
    if(!is_user_logged_in())
    {
        if(isset($_COOKIE['PHPSESSID']))
        {
            $old_id = session_id();
            $new_id = $_COOKIE['PHPSESSID'];
            session_id($new_id);
            require_once('/var/www/common/class.FlipSession.php');
            if(FlipSession::isLoggedIn())
            {
                $flipUser = FlipSession::getUser();
                $wpUser = get_user_by('email', $flipUser->mail);
                if($wpUser !== false)
                {
                    if($flipUser->isInGroupNamed('WordPressAdmins'))
                    {
                        $wpUser->set_role('administrator');
                    }
                    wp_set_current_user($wpUser->ID);
                    wp_set_auth_cookie($wpUser->ID);
                    do_action('wp_login', $wpUser->user_login);
                }
                else
                {
                    $uid = wp_create_user($flipUser->uid, wp_generate_password($length=12, $include_standard_special_chars=false), $flipUser->mail);
                    if($flipUser->isInGroupNamed('WordPressAdmins'))
                    {
                        $wpUser = get_user_by('id', $uid);
                        $wpUser->set_role('administrator');
                    }
                    wp_set_current_user($uid);
                    wp_set_auth_cookie($uid);
                }
            }
            session_id($old_id);
        }
    }
}

add_action('init','flipside_redirect_login_page');

?>
