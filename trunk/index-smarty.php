<?php /* Don't remove these lines, they call the b2 function files ! */

/* $Id$ */

require_once( 'Smarty.class.php' );
$wpsmarty = new Smarty;
$wpsmarty->template_dir = './wp-blogs/main/templates';
$wpsmarty->compile_dir  = './wp-blogs/main/templates_c';
$wpsmarty->cache_dir    = './wp-blogs/main/smartycache';
$wpsmarty->plugin_dir    = './wp-plugins';
require_once( 'b2-include/smarty.inc.php' );
$blog = 1;
require_once('blog.header.php');
require_once($abspath.'wp-links/links.php');
// not on by default: require_once($abspath.'wp-links/links.weblogs.com.php');

define( 'NODISPLAY', false );

$wpsmarty->assign( 'siteurl', $siteurl );
$wpsmarty->assign( 'b2_version', $b2_version );

if($posts) 
{ 
	foreach ($posts as $post) 
	{ 
		start_b2(); 
		$content .= $wpsmarty->fetch( 'post.html' );
		ob_start();
		include($abspath . 'b2comments.php');
		$txt = ob_get_contents();
		ob_end_clean();
		$content .= $txt;
	}
}
else
{
	$content = 'No posts made';
}

$wpsmarty->assign( 'content', $content );
$wpsmarty->display( 'top.html' );

$wpsmarty->display( 'end.html' );

?>
