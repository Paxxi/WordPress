<?php
/**
 * Test WP_User Query, in wp-includes/user.php
 *
 * @group user
 */
class Tests_User_Query extends WP_UnitTestCase {

	protected $user_id;

	function setUp() {
		parent::setUp();

		$this->user_id = $this->factory->user->create( array(
			'role' => 'author'
		) );
	}

	function test_get_and_set() {
		$users = new WP_User_Query();

		$this->assertEquals( '', $users->get( 'fields' ) );
		$this->assertEquals( '', @$users->query_vars['fields'] );

		$users->set( 'fields', 'all' );

		$this->assertEquals( 'all', $users->get( 'fields' ) );
		$this->assertEquals( 'all', $users->query_vars['fields'] );

		$users->set( 'fields', '' );
		$this->assertEquals( '', $users->get( 'fields' ) );
		$this->assertEquals( '', $users->query_vars['fields'] );

		$this->assertNull( $users->get( 'does-not-exist' ) );
	}

	public function test_include_single() {
		$users = $this->factory->user->create_many( 2 );
		$q = new WP_User_Query( array(
			'fields' => '',
			'include' => $users[0],
		) );
		$ids = $q->get_results();

		$this->assertEquals( array( $users[0] ), $ids );
	}

	public function test_include_comma_separated() {
		$users = $this->factory->user->create_many( 3 );
		$q = new WP_User_Query( array(
			'fields' => '',
			'include' => $users[0] . ', ' . $users[2],
		) );
		$ids = $q->get_results();

		$this->assertEqualSets( array( $users[0], $users[2] ), $ids );
	}

	public function test_include_array() {
		$users = $this->factory->user->create_many( 3 );
		$q = new WP_User_Query( array(
			'fields' => '',
			'include' => array( $users[0], $users[2] ),
		) );
		$ids = $q->get_results();

		$this->assertEqualSets( array( $users[0], $users[2] ), $ids );
	}

	public function test_include_array_bad_values() {
		$users = $this->factory->user->create_many( 3 );
		$q = new WP_User_Query( array(
			'fields' => '',
			'include' => array( $users[0], 'foo', $users[2] ),
		) );
		$ids = $q->get_results();

		$this->assertEqualSets( array( $users[0], $users[2] ), $ids );
	}

	function test_exclude() {
		$users = new WP_User_Query();
		$users->set( 'fields', '' );
		$users->set( 'exclude', $this->user_id );
		$users->prepare_query();
		$users->query();

		$ids = $users->get_results();
		$this->assertNotContains( $this->user_id, $ids );
	}

	function test_get_all() {
		$this->factory->user->create_many( 10, array(
			'role' => 'author'
		) );

		$users = new WP_User_Query( array( 'blog_id' => get_current_blog_id() ) );
		$users = $users->get_results();
		$this->assertEquals( 12, count( $users ) );
		foreach ( $users as $user ) {
			$this->assertInstanceOf( 'WP_User', $user );
		}

		$users = new WP_User_Query( array( 'blog_id' => get_current_blog_id(), 'fields' => 'all_with_meta' ) );
		$users = $users->get_results();
		$this->assertEquals( 12, count( $users ) );
		foreach ( $users as $user ) {
			$this->assertInstanceOf( 'WP_User', $user );
		}
	}

	function test_orderby() {
		$user_ids = $this->factory->user->create_many( 10, array(
			'role' => 'author'
		) );

		$names = array( 'd', 'f', 'n', 'f', 'd', 'j', 'r', 'p', 'h', 'g' );

		foreach ( $names as $i => $name )
			update_user_meta( $user_ids[$i], 'last_name', $name );

		$u = new WP_User_Query( array(
			'include' => $user_ids,
			'meta_key' => 'last_name',
			'orderby' => 'meta_value',
			'fields' => 'ids'
		) );
		$values = array();
		foreach ( $u->get_results() as $user )
			$values[] = get_user_meta( $user, 'last_name', true );

		sort( $names );

		$this->assertEquals( $names, $values );
	}

	/**
	 * @ticket 30064
	 */
	public function test_orderby_include_with_empty_include() {
		$q = new WP_User_Query( array(
			'orderby' => 'include',
		) );

		$this->assertContains( 'ORDER BY user_login', $q->query_orderby );
	}

	/**
	 * @ticket 30064
	 */
	public function test_orderby_include() {
		global $wpdb;

		$users = $this->factory->user->create_many( 4 );
		$q = new WP_User_Query( array(
			'orderby' => 'include',
			'include' => array( $users[1], $users[0], $users[3] ),
			'fields' => '',
		) );

		$expected_orderby = 'ORDER BY FIELD( ' . $wpdb->users . '.ID, ' . $users[1] . ',' . $users[0] . ',' . $users[3] . ' )';
		$this->assertContains( $expected_orderby, $q->query_orderby );

		// assertEquals() respects order but ignores type (get_results() returns numeric strings).
		$this->assertEquals( array( $users[1], $users[0], $users[3] ), $q->get_results() );
	}

	/**
	 * @ticket 30064
	 */
	public function test_orderby_include_duplicate_values() {
		global $wpdb;

		$users = $this->factory->user->create_many( 4 );
		$q = new WP_User_Query( array(
			'orderby' => 'include',
			'include' => array( $users[1], $users[0], $users[1], $users[3] ),
			'fields' => '',
		) );

		$expected_orderby = 'ORDER BY FIELD( ' . $wpdb->users . '.ID, ' . $users[1] . ',' . $users[0] . ',' . $users[3] . ' )';
		$this->assertContains( $expected_orderby, $q->query_orderby );

		// assertEquals() respects order but ignores type (get_results() returns numeric strings).
		$this->assertEquals( array( $users[1], $users[0], $users[3] ), $q->get_results() );
	}

	/**
	 * @ticket 21119
	 */
	function test_prepare_query() {
		$query = new WP_User_Query();
		$this->assertEmpty( $query->query_fields );
		$this->assertEmpty( $query->query_from );
		$this->assertEmpty( $query->query_limit );
		$this->assertEmpty( $query->query_orderby );
		$this->assertEmpty( $query->query_where );
		$this->assertEmpty( $query->query_vars );
		$_query_vars = $query->query_vars;

		$query->prepare_query();
		$this->assertNotEmpty( $query->query_fields );
		$this->assertNotEmpty( $query->query_from );
		$this->assertEmpty( $query->query_limit );
		$this->assertNotEmpty( $query->query_orderby );
		$this->assertNotEmpty( $query->query_where );
		$this->assertNotEmpty( $query->query_vars );
		$this->assertNotEquals( $_query_vars, $query->query_vars );

		// All values get reset
		$query->prepare_query( array( 'number' => 8 ) );
		$this->assertNotEmpty( $query->query_limit );
		$this->assertEquals( 'LIMIT 8', $query->query_limit );

		// All values get reset
		$query->prepare_query( array( 'fields' => 'all' ) );
		$this->assertEmpty( $query->query_limit );
		$this->assertEquals( '', $query->query_limit );
		$_query_vars = $query->query_vars;

		$query->prepare_query();
		$this->assertEquals( $_query_vars, $query->query_vars );
	}
}
