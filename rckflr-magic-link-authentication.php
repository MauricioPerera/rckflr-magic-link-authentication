<?php
/**
 * Plugin Name: Magic Link Authentication
  * Description: Este plugin de WordPress implementa un sistema de autenticación mediante un enlace mágico. Los usuarios reciben un enlace único en su correo electrónico que les permite iniciar sesión sin necesidad de una contraseña.
 * Version: 1.0
 * Author: Mauricio Perera
 * Author URI: https://www.linkedin.com/in/mauricioperera/
 * Donate link: https://www.buymeacoffee.com/rckflr
 */

session_start(); // Start session to store messages

// Hook for adding admin menus
add_action('admin_menu', 'magic_link_menu');

// Action for adding menu
function magic_link_menu() {
    add_menu_page('Magic Link Settings', 'Magic Link', 'manage_options', 'magic_link', 'magic_link_page');
}

// Function to display the admin page
function magic_link_page() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        update_option('magic_link_nonce_lifetime', intval($_POST['nonce_lifetime']));
        update_option('magic_link_registered_message', sanitize_text_field($_POST['registered_message']));
        update_option('magic_link_new_user_message', sanitize_text_field($_POST['new_user_message']));
        update_option('magic_link_email_subject', sanitize_text_field($_POST['email_subject']));
        update_option('magic_link_email_body', sanitize_text_field($_POST['email_body']));
		update_option('magic_link_redirect_url', sanitize_text_field($_POST['redirect_url']));
    }

    $nonce_lifetime = get_option('magic_link_nonce_lifetime', 15);
    $registered_message = get_option('magic_link_registered_message', 'We will send a Magic Link to your email address.');
    $new_user_message = get_option('magic_link_new_user_message', 'We have created your account. A Magic Link will be sent to your email.');
    $email_subject = get_option('magic_link_email_subject', 'Your Magic Link');
    $email_body = get_option('magic_link_email_body', 'Click here to login: [magic_link_url]');
	$redirect_url = get_option('magic_link_redirect_url', home_url());

    ?>
    <div class="wrap">
        <h2>Magic Link Settings</h2>
        <form method="post" action="">
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="nonce_lifetime">Nonce Lifetime (minutes)</label></th>
                    <td><input type="number" id="nonce_lifetime" name="nonce_lifetime" value="<?php echo $nonce_lifetime; ?>"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="registered_message">Message for Registered Users</label></th>
                    <td><input type="text" id="registered_message" name="registered_message" value="<?php echo $registered_message; ?>"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="new_user_message">Message for New Users</label></th>
                    <td><input type="text" id="new_user_message" name="new_user_message" value="<?php echo $new_user_message; ?>"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="email_subject">Email Subject</label></th>
                    <td><input type="text" id="email_subject" name="email_subject" value="<?php echo $email_subject; ?>"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="email_body">Email Body</label></th>
                    <td><textarea id="email_body" name="email_body"><?php echo $email_body; ?></textarea></td>
                </tr>
				<tr>
                    <th scope="row"><label for="redirect_url">Redirect URL</label></th>
                    <td><input type="text" id="redirect_url" name="redirect_url" value="<?php echo $redirect_url; ?>"></td>
                </tr>
            </table>
            <p class="submit">
                <input type="submit" class="button-primary" value="Save Changes">
            </p>
        </form>
    </div>
    <?php
}

// Generate and send magic link
add_action('init', function() {
    if(isset($_POST['magic_email'])) {
        $email = sanitize_email($_POST['magic_email']);
        $user = get_user_by('email', $email);

        if ($user) {
            $_SESSION['magic_message'] = get_option('magic_link_registered_message', 'We will send a Magic Link to your email address.');
        } else {
            $_SESSION['magic_message'] = get_option('magic_link_new_user_message', 'We have created your account. A Magic Link will be sent to your email.');
            $random_password = wp_generate_password();
            $user_id = wp_create_user($email, $random_password, $email);
            $user = get_user_by('ID', $user_id);
        }

        $nonce = wp_create_nonce($user->ID);
        $_SESSION['real_nonce'] = $nonce;
        $magic_link = add_query_arg([
            'action' => 'magic_login',
            'email' => $email,
            '_wpnonce' => $nonce,
        ], home_url());

        $email_body = str_replace('[magic_link_url]', $magic_link, get_option('magic_link_email_body', 'Click here to login: [magic_link_url]'));
        wp_mail($email, get_option('magic_link_email_subject', 'Your Magic Link'), $email_body);
    }
});

// Shortcode for login form
function magic_link_login_form() {
    ob_start();
    ?>
    <form method="post" action="">
        <label for="magic_email">Email:</label>
        <input type="email" name="magic_email" id="magic_email" required>
        <input type="submit" value="Send Magic Link">
    </form>
    <?php
    if (isset($_SESSION['magic_message'])) {
        echo '<p>' . $_SESSION['magic_message'] . '</p>';
        unset($_SESSION['magic_message']);
    }
    return ob_get_clean();
}
add_shortcode('magic_link_login', 'magic_link_login_form');

// Hook to validate magic link
add_action('init', function() {
	$redirect_url = get_option('magic_link_redirect_url', home_url());
    if(isset($_GET['action']) && $_GET['action'] === 'magic_login') {
        $email = sanitize_email($_GET['email']);
        $url = home_url() . $_SERVER['REQUEST_URI'];

        if(cwpai_verify_nonce_for_user($url, $email)) {
            $user = get_user_by('email', $email);
            wp_set_auth_cookie($user->ID, true);
            wp_redirect($redirect_url);
            exit;
        } else {
            wp_redirect(home_url('/404'));
            exit;
        }
    }
});

// Verify nonce for user with email
function cwpai_verify_nonce_for_user( $url, $email ) {
    $user = get_user_by( 'email', $email );
    if ( ! $user ) {
        return false;
    }

    $query_args = wp_parse_url( $url, PHP_URL_QUERY );
    parse_str( $query_args, $query_args );

    if ( ! isset( $query_args['_wpnonce'] ) ) {
        return false;
    }

    $nonce = $query_args['_wpnonce'];
    $is_valid_nonce = wp_verify_nonce( $nonce, $user->ID );
    return $is_valid_nonce;
}
