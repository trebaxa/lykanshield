<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class MultisiteEntitlementTest extends TestCase
{
    protected function setUp(): void
    {
        lykanshield_test_reset();
        $GLOBALS['lykanshield_test_multisite'] = true;
    }

    public function testSubdomainsShareMainDomainEntitlementButDifferentTldDoesNot(): void
    {
        $GLOBALS['lykanshield_test_site_options'][LykanShield_Multisite::NETWORK_TOKENS_OPTION] = [
            'example.de' => 'premium-token',
        ];

        self::assertSame('premium-token', LykanShield_Multisite::token_for_domain('example.de'));
        self::assertSame('premium-token', LykanShield_Multisite::token_for_domain(
            LykanShield_Domain_Resolver::registrable_domain('shop.example.de')
        ));
        self::assertSame('', LykanShield_Multisite::token_for_domain(
            LykanShield_Domain_Resolver::registrable_domain('example.com')
        ));
    }

    public function testNetworkCapabilityIsRequiredOnlyOnNetworkAdminScreen(): void
    {
        $GLOBALS['lykanshield_test_network_admin'] = false;
        self::assertSame('manage_options', LykanShield_Multisite::required_capability());

        $GLOBALS['lykanshield_test_network_admin'] = true;
        self::assertSame('manage_network_options', LykanShield_Multisite::required_capability());
    }
}
