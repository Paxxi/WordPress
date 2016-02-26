<?php

/**
 * @group l10n
 * @group i18n
 */
class Tests_L10n_GetLocale extends WP_UnitTestCase {
	public function test_should_respect_locale_global() {
		global $locale;
		$old_locale = $locale;

		$locale = 'foo';

		$found = get_locale();
		$locale = $old_locale;

		$this->assertSame( 'foo', $found );
	}

	public function test_local_option_should_take_precedence_on_multisite() {
		global $locale;
		$old_locale = $locale;
		$locale = null;

		if ( ! is_multisite() ) {
			$this->markTestSkipped( __METHOD__ . ' requires Multisite' );
		}

		update_option( 'WPLANG', 'en_GB' );
		update_site_option( 'WPLANG', 'es_ES' );

		$found = get_locale();
		$locale = $old_locale;

		$this->assertSame( 'en_GB', $found );
	}

	public function test_network_option_should_be_fallback_on_multisite() {
		global $locale;
		$old_locale = $locale;
		$locale = null;

		if ( ! is_multisite() ) {
			$this->markTestSkipped( __METHOD__ . ' requires Multisite' );
		}

		update_site_option( 'WPLANG', 'es_ES' );

		$found = get_locale();
		$locale = $old_locale;

		$this->assertSame( 'es_ES', $found );
	}

	public function test_option_should_be_respected_on_nonmultisite() {
		global $locale;
		$old_locale = $locale;
		$locale = null;

		if ( is_multisite() ) {
			$this->markTestSkipped( __METHOD__ . ' does not apply to Multisite' );
		}

		update_option( 'WPLANG', 'es_ES' );

		$found = get_locale();
		$locale = $old_locale;

		$this->assertSame( 'es_ES', $found );

	}

	public function test_should_fall_back_on_en_US() {
		global $locale;
		$old_locale = $locale;
		$locale = null;

		$found = get_locale();
		$locale = $old_locale;

		$this->assertSame( 'en_US', $found );
	}

	public function test_should_respect_get_locale_filter() {
		add_filter( 'locale', array( $this, 'filter_get_locale' ) );
		$found = get_locale();
		remove_filter( 'locale', array( $this, 'filter_get_locale' ) );

		$this->assertSame( 'foo', $found );
	}

	public function filter_get_locale() {
		return 'foo';
	}
}
