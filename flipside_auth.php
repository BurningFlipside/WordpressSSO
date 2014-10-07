<?php
/**
 * Plugin Name: Flipside Auth Plugin
 * Plugin URI: https://dev.burningflipside.com
 * Description: Flipside Auth.
 * Version: 0.1
 * Author: Patrick
 */


function flipside_redirect_login_page()
{
    if(strpos($_SERVER['REQUEST_URI'], 'wp-login.php'))
    {
        $redirect = site_url();
        if(isset($_GET['redirect_to']))
        {
            $redirect = $_GET['redirect_to'];
        }
        wp_redirect('https://profiles.burningflipside.com/login.php?return='.$redirect);
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
            if(FlipSession::is_logged_in())
            {
                $flipUser = FlipSession::get_user(TRUE);
                $wpUser = get_user_by('email', $flipUser->mail[0]);
                if($wpUser !== false)
                {
                    if($flipUser->isInGroupNamed('WordPressAdmins'))
                    {
                        $wpUser->add_role('Administrator');
                    }
                    wp_set_current_user($wpUser->ID);
                    wp_set_auth_cookie($wpUser->ID);
                }
                else
                {
                    $uid = wp_create_user($flipUser->uid[0], wp_generate_password($length=12, $include_standard_special_chars=false), $flipUser->mail[0]);
                    if($flipUser->isInGroupNamed('WordPressAdmins'))
                    {
                        $wpUser = get_user_by('id', $uid);
                        $wpUser->add_role('Administrator');
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