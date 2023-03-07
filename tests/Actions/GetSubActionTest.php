<?php

namespace Tests\Actions;

use Tests\TestCase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Request;
use Yomafleet\CognitoAuthenticator\Actions\GetSubAction;
use Yomafleet\CognitoAuthenticator\Factories\TokenFactory;
use Yomafleet\CognitoAuthenticator\Factories\UserPoolFactory;
use Yomafleet\CognitoAuthenticator\Contracts\TokenFactoryContract;

class GetSubActionTest extends TestCase
{
    public function test_get_sub()
    {
        $request = Request::instance();
        $request->headers->set('Authorization', 'Bearer '.$this->dummyJWT(), true);
        $userPoolId = env('AWS_COGNITO_USER_POOL_ID');
        $region = env('AWS_REGION');

        Http::fake([
            "https://cognito-idp.ap-southeast-1.amazonaws.com/{$userPoolId}/.well-known/jwks.json" => Http::response([
                'token_use' => 'access',
                'iss' => "https://cognito-idp.{$region}.amazonaws.com/{$userPoolId}",
                'keys' => $this->dummyKeys(),
            ])
        ]);

        $getSub = new GetSubAction(
            $request,
            new UserPoolFactory(),
            $this->getTokenFactoryDouble());

        $sub = $getSub();

        $this->assertNotNull($sub);
        $this->assertTrue(is_string($sub));
        $this->assertTrue(strlen($sub) > 0);
    }

    protected function dummyJWT()
    {
        $header = "eyJraWQiOiIrR2xCOXpYZVhcL3hYTm5McWwxZHAzaUllcUc4blVmV0s0Y3JlV1pwM3NUYz0iLCJhbGciOiJSUzI1NiJ9";
        $body = "eyJzdWIiOiJkNGM4NWM0YS1lZjFjLTRhNjMtODY1MS1hMjRmMmVjN2VlNjciLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuYXAtc291dGhlYXN0LTEuYW1hem9uYXdzLmNvbVwvYXAtc291dGhlYXN0LTFfN2cwNDkyWGtJIiwidmVyc2lvbiI6MiwiY2xpZW50X2lkIjoiNTdmdmI3NWRkMXA5M3JpNjZmdXQyb2JmZjQiLCJvcmlnaW5fanRpIjoiNzAxNDQ3MDctN2EyNC00OWNmLWE3MzQtMTgyMTViYTJkZTVjIiwiZXZlbnRfaWQiOiI5NWFkYTljZi0wZDY5LTQ0YWQtOTljMC1hY2M0MTY1YWRhMmIiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiYXV0aF90aW1lIjoxNjc4MTY2NTM2LCJleHAiOjE2NzgyNTI5NjUsImlhdCI6MTY3ODE2NjU2NSwianRpIjoiMmU5NDlkMWUtOGFjZS00ZjI0LWFkMjAtNGRjNjkzN2RkZmExIiwidXNlcm5hbWUiOiJkNGM4NWM0YS1lZjFjLTRhNjMtODY1MS1hMjRmMmVjN2VlNjcifQ";
        $meta = "OVDTGHTMfdMXusVSseNDhmKZHw2I033xsK2qP2FtvBmY3Qo-oscNf8PMPpgRn4Rj5KKlWTttN3dd4mn3l8J6IuCU8YjXGItRPKjU7Xwx4l4G7P09X4Wtua2aaYkPRIo6MVnvalNhoVNc9wDLFtauoUufGnfBT4JGq7rYLOUvOS1CP4cC16hhayftRtQ2HlWPnBfon5bJx2CJVlzlfbf8S7jZuFrDzjbZJlswiH-4NDH47Acj7cvCGr6a0rJmI2iSPFiwoYTPKYrzf0CwiGy6J6EuOcY2NNyehnkGsLhMddj44onJ9N1F8DolOiKns6dmQRHvkFc-jWuIk7qSF7hrew";
        
        return $header.'.'.$body.'.'.$meta;
    }

    protected function dummyKeys()
    {
        return [
            [
              "alg" => "RS256",
              "e" => "AQAB",
              "kid" => "uDeqDayP2w9+YMaxTRL/CBD76cVI5f/2walx3Xss77w=",
              "kty" => "RSA",
              "n" => "uCPkuhnIoQikU0FgxjQCd2jUsyL0pYZPdPwXPe-O-iueS1c6gFZ_XWcSseYP4GhdxHfMhrfqwIabEB9tvRlVFwB5nauUyLXBh5cpeur-rkeBxN_oa1ey_5YGlBTJB1o9Pkn78WwgAY2H17tmS4CrwgkJn6n5042m09z9cq77G_OrD71ffRafMc7LEVIVHNPqq6WZuPP-yVxOGF7H8R8czTuEicXLf-6ALKqxfUHyr3kuYyF_yfoLCkH3GgI8rJQu2ktvSxDtBBY-vHcXKk6Fifdam9l7HSAh9OIuiACWzkcLt5gN65-zaYtpo7sRtSyjM3dWM_1Ab4RZyy6kdC7afQ",
              "use" => "sig"
            ],
            [
              "alg" => "RS256",
              "e" => "AQAB",
              "kid" => "+GlB9zXeX/xXNnLql1dp3iIeqG8nUfWK4creWZp3sTc=",
              "kty" => "RSA",
              "n" => "p1kXacqqD7aNcxt2o0e5xkqO_GclT3LOYGSanMTSUrN22hQP5MxaV75kCBqbW5UGdWz0gmowH3SKB6rlL_IFmcmCb9xXaPoeh6As0GWArK090F_-xHpVqgIAF7UOgt-hlYXcPphgPCqL6yODK-fUd-2Z3cJfk1kXD3MHf74T9z9dJb-InMIGE6t7RVQXXBHWtEhozNEb5UNwMx9k04nctDv8s0mi2YLDdrD6VzWRNBv8pe8YHY3My9GdJZnXo-0NCAvmD6JrYe-jZh22IlaBLiGW09s8dMDY7c8NHfH8PzwpKMl2QCFje5Fv_BV6lm-mnMYpcZhoSDTUvGNtD7RuOw",
              "use" => "sig"
            ]
        ];
    }

    protected function getTokenFactoryDouble()
    {
        return new class extends TokenFactory implements TokenFactoryContract
            {
                public function prepareClaims(array $claims, array $requiredClaims): array
                {
                    $claims = parent::prepareClaims($claims, $requiredClaims);

                    $userPoolId = env('AWS_COGNITO_USER_POOL_ID');
                    $region = env('AWS_REGION');
                    $fakeIssuerUrl = "https://cognito-idp.{$region}.amazonaws.com/{$userPoolId}";
                    $claims['iss'] = $fakeIssuerUrl;

                    return $claims;
                }
            };
    }
}
