<?php
/**
 * WordPress Administration for Navigation Menus
 * Interface functions
 *
 * @version 2.0.0
 *
 * @package WordPress
 * @subpackage Administration
 */

/** Load WordPress Administration Bootstrap */
require_once( 'admin.php' );

// Permissions Check
if ( ! current_user_can('switch_themes') )
	wp_die( __( 'Cheatin&#8217; uh?' ));

// Nav Menu CSS
wp_admin_css( 'nav-menu' );

// jQuery
wp_enqueue_script( 'jquery' );
wp_enqueue_script( 'jquery-ui-draggable' );
wp_enqueue_script( 'jquery-ui-droppable' );
wp_enqueue_script( 'jquery-ui-sortable' );
wp_enqueue_script( 'jquery-autocomplete' );

// Nav Menu functions
wp_enqueue_script( 'nav-menu-dynamic-functions' );
wp_enqueue_script( 'nav-menu-default-items' );
wp_enqueue_script( 'nav-menu-php-functions' );

// Metaboxes
wp_enqueue_script( 'common' );
wp_enqueue_script( 'wp-lists' );
wp_enqueue_script( 'postbox' );

// Thickbox
add_thickbox();

// Load all the nav menu interface functions
require_once( ABSPATH . 'wp-admin/includes/nav-menu.php' );

// Container for any messages displayed to the user
$messages_div = '';

// Container that stores the name of the active menu
$nav_menu_selected_title = '';

// The menu id of the current menu being edited
$nav_menu_selected_id = isset( $_REQUEST['menu'] ) ? (int) $_REQUEST['menu'] : 0;

// Allowed actions: add, update, delete
$action = isset( $_REQUEST['action'] ) ? $_REQUEST['action'] : 'edit';

switch ( $action ) {
	case 'delete':
		check_admin_referer( 'delete-nav_menu-' . $nav_menu_selected_id );

		if ( is_nav_menu($nav_menu_selected_id) ) {
			wp_delete_nav_menu( $nav_menu_selected_id );
			$messages_div = '<div id="message" class="updated fade below-h2"><p>' . __('Menu successfully deleted.') . '</p></div>';
			$nav_menu_selected_id = 0;
		}
		break;
	
	case 'update':
		check_admin_referer( 'update-nav_menu' );
		
		// Add Menu
		if ( isset($_POST['create-menu']) ) {
			if ( current_theme_supports('nav-menus') ) {
				$add_nav_menu = esc_html( $_POST['create-menu-name'] );

				if ( $add_nav_menu ) {
					$add_nav_menu = wp_create_nav_menu( $add_nav_menu );

					if ( is_wp_error( $add_nav_menu ) ) {
						$messages_div = '<div id="message" class="error fade below-h2"><p>' . $add_nav_menu->get_error_message() . '</p></div>';
					} else {
						$nav_menu_selected_id = $add_nav_menu->term_id;
						$nav_menu_selected_title = $add_nav_menu->name;
						$messages_div = '<div id="message" class="updated fade below-h2"><p>' . sprintf( __('The <strong>%s</strong> menu has been successfully created.'), esc_html( $add_nav_menu->name ) ) . '</p></div>';
					}
				} else {
					$messages_div = '<div id="message" class="error fade below-h2"><p>' . __('Please enter a valid menu name.') . '</p></div>';
				}
				unset($add_nav_menu);
			}
		}
		
		// Update menu name
		if ( isset($_POST['menu-name']) ) {
			$old_nav_menu = get_term( $nav_menu_selected_id, 'nav_menu', ARRAY_A );
			$args = array( 'name' => $_POST['menu-name'], 'slug' => null, 'description' => $old_nav_menu['description'], 'parent' => $old_nav_menu['parent'], );
			$new_nav_menu = wp_update_term( $nav_menu_selected_id, 'nav_menu', $args );
		}
		
		// Update menu items
		$update_nav_items = isset( $_POST['li-count'] ) ? (int) $_POST['li-count'] : 0;
		$update_nav_menu = is_nav_menu( $nav_menu_selected_id );
		
		if ( !is_wp_error($update_nav_menu) ) {
			$menu_items = wp_get_nav_menu_items( $nav_menu_selected_id, array('orderby' => 'ID', 'output' => ARRAY_A, 'output_key' => 'ID') );
			$parent_menu_ids = array();
			
			// Loop through all POST variables
			for ( $k = 0; $k < $update_nav_items; $k++ ) {
				
				$menu_item_db_id 		= isset( $_POST['menu-item-db-id'][$k] )		? $_POST['menu-item-db-id'][$k] 	: 0;
				$menu_item_object_id 	= isset( $_POST['menu-item-object-id'][$k] ) 	? $_POST['menu-item-object-id'][$k] : 0;
				$menu_item_parent_id 	= isset( $_POST['menu-item-parent-id'][$k] ) 	? $_POST['menu-item-parent-id'][$k] : 0;
				$menu_item_position 	= isset( $_POST['menu-item-position'][$k] ) 	? $_POST['menu-item-position'][$k] 	: 0;
				$menu_item_type 		= isset( $_POST['menu-item-type'][$k] )	 		? $_POST['menu-item-type'][$k] 		: 'custom';
				$menu_item_append 		= isset( $_POST['menu-item-append'][$k] )	 	? $_POST['menu-item-append'][$k]	: 'custom';
				
				$menu_item_title 		= isset( $_POST['menu-item-title'][$k] ) 		? $_POST['menu-item-title'][$k] 	: '';
				$menu_item_url 			= isset( $_POST['menu-item-url'][$k] ) 			? $_POST['menu-item-url'][$k] 		: '';
				$menu_item_description 	= isset( $_POST['menu-item-description'][$k] ) 	? $_POST['menu-item-description'][$k]: '';
				$menu_item_attr_title  	= isset( $_POST['menu-item-attr-title'][$k] ) 	? $_POST['menu-item-attr-title'][$k] : '';
				$menu_item_target 		= isset( $_POST['menu-item-target'][$k] ) 		? $_POST['menu-item-target'][$k] 	: 0;
				$menu_item_classes 		= isset( $_POST['menu-item-classes'][$k] ) 		? $_POST['menu-item-classes'][$k] 	: '';
				$menu_item_xfn	 		= isset( $_POST['menu-item-xfn'][$k] )	 		? $_POST['menu-item-xfn'][$k] 		: '';
				
				// Menu item title can't be blank
				if ( '' == $menu_item_title )
					continue;
				
				// Populate the menu item
				$post = array( 'post_status' => 'publish', 'post_type' => 'nav_menu_item', 'post_author' => $user_ID,
					'ping_status' => 0, 'post_parent' => $menu_item_parent_id, 'menu_order' => $menu_item_position,
					'post_excerpt' => $menu_item_attr_title, 'tax_input' => array( 'nav_menu' => $update_nav_menu->name ),
					'post_content' => $menu_item_description, 'post_title' => $menu_item_title );

				// New menu item
				if ( $menu_item_db_id == 0 ) {
					$menu_item_db_id = wp_insert_post( $post );
				} elseif ( isset( $menu_items[$menu_item_db_id] ) ) {
					$post['ID'] = $menu_item_db_id;
					wp_update_post( $post );
					unset( $menu_items[$menu_item_db_id] );
				}
				$parent_menu_ids[$k] = $menu_item_db_id;
				
				update_post_meta( $menu_item_db_id, 'menu_item_type', $menu_item_type );
				update_post_meta( $menu_item_db_id, 'menu_item_append', $menu_item_append );
				update_post_meta( $menu_item_db_id, 'menu_item_object_id', $menu_item_object_id );
				update_post_meta( $menu_item_db_id, 'menu_item_target', esc_attr($menu_item_target) );
				update_post_meta( $menu_item_db_id, 'menu_item_classes', esc_attr($menu_item_classes) );
				update_post_meta( $menu_item_db_id, 'menu_item_xfn', esc_attr($menu_item_xfn) );
				
				// @todo: only save custom link urls.
				update_post_meta( $menu_item_db_id, 'menu_item_url', esc_url_raw( $menu_item_url ) );
			}
			
			// Remove menu items from the menu that weren't in $_POST
			if ( !empty( $menu_items ) ) {
				foreach ( array_keys( $menu_items ) as $menu_item_id ) {
					wp_delete_post( $menu_item_id );
				}
			}
			$messages_div = '<div id="message" class="updated fade below-h2"><p>' . __('The menu has been updated.') . '</p></div>';
		}
		break;
}

// Get all nav menus
$nav_menus = wp_get_nav_menus();

// Get recently edited nav menu
$recently_edited = get_user_option( 'nav_menu_recently_edited' );

// If there was no recently edited menu, and $nav_menu_selected_id is a nav menu, update recently edited menu.
if ( !$recently_edited && is_nav_menu($nav_menu_selected_id) ) {
	$recently_edited = $nav_menu_selected_id;

// Else if $nav_menu_selected_id is not a menu, but $recently_edited is, grab that one.
} elseif ( 0 == $nav_menu_selected_id && is_nav_menu($recently_edited) ) {
	$nav_menu_selected_id = $recently_edited;

// Else try to grab the first menu from the menus list
} elseif ( 0 == $nav_menu_selected_id && ! empty($nav_menus) ) {
	$nav_menu_selected_id = $nav_menus[0]->term_id;	
}

// Update the user's setting
if ( $nav_menu_selected_id != $recently_edited && is_nav_menu($nav_menu_selected_id) )
	update_user_meta( $current_user->ID, 'nav_menu_recently_edited', $nav_menu_selected_id );

// If there's a menu, get it's name.
if ( !$nav_menu_selected_title && $nav_menu_selected_title = is_nav_menu( $nav_menu_selected_id ) ) {
	$nav_menu_selected_title = $nav_menu_selected_title->name;
}

// The user has no menus.
if ( !is_nav_menu( $nav_menu_selected_id ) ) {
	if ( current_theme_supports('nav-menus') ) {
		$messages_div = '<div id="message" class="updated"><p>' . __('You haven\'t setup any menus yet. Create a new menu.') . '</p></div>';
	} else {
		$messages_div = '<div id="message" class="error"><p>' . __('The current theme does not support menus.') . '</p></div>';
	}
} else {
	add_meta_box( 'manage-menu', __( 'Menu Settings' ), 'wp_nav_menu_manage_menu_metabox', 'menus', 'side', 'high', array( $nav_menu_selected_id, $nav_menu_selected_title ) );
}

// Get the admin header
require_once( 'admin-header.php' );
?>
<div class="wrap">
	<?php screen_icon(); ?>
	<h2><?php esc_html_e('Menus'); ?></h2>
	<?php echo $messages_div; ?>
	<div class="hide-if-js error"><p><?php _e('You do not have JavaScript enabled in your browser. Please enable it to access the Menus functionality.'); ?></p></div>

	<?php if ( !empty($nav_menus) && count($nav_menus) > 1 ) : ?>
	<ul class="subsubsub">
		<?php
			foreach ( $nav_menus as $_nav_menu ) {
				$sep = end( $nav_menus ) == $_nav_menu ? '' : ' | ';
				
				if ( $nav_menu_selected_id == $_nav_menu->term_id )
					echo '<li><a href="'. admin_url( 'nav-menus.php?action=edit&amp;menu=' . esc_attr($_nav_menu->term_id) ) .'" class="current">'. esc_html( $_nav_menu->name ) .'</a>'. $sep .'</li>';
				else
					echo '<li><a href="'. admin_url( 'nav-menus.php?action=edit&amp;menu=' . esc_attr($_nav_menu->term_id) ) .'">'. esc_html( $_nav_menu->name ) .'</a>'. $sep .'</li>';
			}
		?>
	</ul>
	<?php endif; ?>

	<div id="menu-management" class="metabox-holder has-right-sidebar">
		<form id="update-nav-menu" onsubmit="wp_update_post_data();" action="<?php echo admin_url( 'nav-menus.php' ); ?>" method="post" enctype="multipart/form-data">
			<?php wp_nonce_field( 'closedpostboxes', 'closedpostboxesnonce', false ); ?>
			<?php wp_nonce_field( 'meta-box-order', 'meta-box-order-nonce', false ); ?>
			<?php wp_nonce_field( 'update-nav_menu' ); ?>
			<input type="hidden" name="action" value="update" />
			<input type="hidden" name="li-count" id="li-count" value="0" />
			<input type="hidden" name="menu" id="menu" value="<?php echo esc_attr( $nav_menu_selected_id ); ?>" />
			
			<div id="post-body">
				<div id="post-body-content">
					<?php if ( is_nav_menu($nav_menu_selected_id) ) : ?>
						<div id="menu-container" class="postbox">
							<h3 class="hndle"><?php echo esc_html( $nav_menu_selected_title ); ?></h3>
							<div class="inside">
								
								<?php echo wp_get_nav_menu( array( 'context' => 'backend', 'menu' => $nav_menu_selected_id ) ); ?>
								
							</div><!-- /.inside -->
						<!-- /#nav-menu-canvas .postbox-->
						</div>
						<script type="text/javascript">
							wp_update_post_data();
						</script>
					<?php endif; ?>
				</div><!-- /#post-body-content-->
			</div><!--- /#post-body -->
			<div id="menu-settings-column" class="inner-sidebar">
				
				<?php do_meta_boxes( 'menus', 'side', null ); ?>
				
			</div><!-- /#menu-settings-column -->
		</form><!--/#update-nav-menu-->
		<br class="clear" />
	</div><!-- /.metabox-holder has-right-sidebar-->
</div><!-- /.wrap-->

<div id="menu-item-settings">
	<p class="description">
		<label for="edit-menu-item-title">
			<?php _e( 'Menu Title' ); ?><br />
			<input type="text" id="edit-menu-item-title" class="widefat" name="edit-menu-item-title" value="" tabindex="1" />
		</label>
	</p>
	<p class="description">
		<label for="edit-menu-item-url">
			<?php _e( 'URL' ); ?><br />
			<input type="text" id="edit-menu-item-url" class="widefat code" name="edit-menu-item-url" value="" tabindex="2" />
		</label>
	</p>
	<p class="description">
		<label for="edit-menu-item-attr-title">
			<?php _e( 'Title Attribute' ); ?><br />
			<input type="text" id="edit-menu-item-attr-title" class="widefat" name="edit-menu-item-attr-title" value="" tabindex="3" />
		</label>
	</p>
	<p class="description">
		<label for="edit-menu-item-target">
			<?php _e( 'Link Target' ); ?><br />
			<select id="edit-menu-item-target" class="widefat" name="edit-menu-item-target" tabindex="4">
				<option value="_self">Same window or tab</option>
				<option value="_blank">New window or tab</option>
			</select>
		</label>
	</p>
	<p class="description">
		<label for="edit-menu-item-classes">
			<?php _e( 'CSS Classes (optional)' ); ?><br />
			<input type="text" id="edit-menu-item-classes" class="widefat code" name="edit-menu-item-classes" value="" tabindex="5" />
		</label>
	</p>
	<p class="description">
		<label for="edit-menu-item-xfn">
			<?php _e( 'Link Relationship (XFN) (optional)' ); ?><br />
			<input type="text" id="edit-menu-item-xfn" class="widefat code" name="edit-menu-item-xfn" value="" tabindex="6" />
		</label>
	</p>
	<p class="description">
		<label for="edit-menu-item-description">
			<?php _e( 'Description (optional)' ); ?><br />
			<textarea id="edit-menu-item-description" class="widefat" rows="3" name="edit-menu-item-description" tabindex="7" /></textarea>
			<span class="description">The description will be displayed in the menu if the current theme supports it.</span>
		</label>
	</p>
	<p>
		<a id="update-menu-item" class="save button-primary" tabindex="8"><?php _e('Save Changes'); ?></a>
		<a id="cancel-save" class="submitdelete deletion" tabindex="9"><?php _e('Cancel'); ?></a>
	</p>
	<input type="hidden" id="edit-menu-item-id" name="edit-item-id" value="" />
</div><!-- /#menu-item-settings-->

<?php include( 'admin-footer.php' ); ?>