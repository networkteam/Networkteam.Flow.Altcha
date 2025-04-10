<?php

namespace Networkteam\Flow\Altcha\Validation\Validator;

use Neos\Flow\Validation\Validator\AbstractValidator;
use Networkteam\Flow\Altcha\Service\AltchaService;
use Neos\Flow\Annotations as Flow;

/***************************************************************
 *  (c) 2025 networkteam GmbH - all rights reserved
 ***************************************************************/

class CaptchaValidator extends AbstractValidator
{

    protected $supportedOptions = [
        'algorithm' => [null, 'Hashing algorithm to use (`SHA-1`, `SHA-256`, `SHA-512`, default:`SHA-256`', 'string'],
        'minNumber' => [null, 'Minimum number for the random number generator (default: 5,0000)', 'integer'],
        'maxNumber' => [null, 'Maximum number for the random number generator (default: 1,000,000)', 'integer'],
        'expires' => [null, 'Expiration time for the challenge in seconds', 'integer'],
        'saltLength' => [null, 'Length of the random salt (default: 12 bytes).', 'integer']
    ];

    protected $acceptsEmptyValues = false;

    #[Flow\Inject]
    protected AltchaService $altchaService;

    protected function isValid($value)
    {
        if(!$value) {
            $this->addError('The value must not be empty', 1744199569);
        }
        if ($this->altchaService->validate($value) === false) {
            $this->addError('Captcha validation failed.', 1744199570);
        }
    }
}