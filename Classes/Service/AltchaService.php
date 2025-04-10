<?php

namespace Networkteam\Flow\Altcha\Service;

use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\BaseChallengeOptions;
use AltchaOrg\Altcha\ChallengeOptions;
use AltchaOrg\Altcha\Hasher\Algorithm;
use Neos\Flow\Configuration\Exception\InvalidConfigurationException;
use Neos\Flow\Annotations as Flow;

/***************************************************************
 *  (c) 2025 networkteam GmbH - all rights reserved
 ***************************************************************/

#[Flow\Scope("singleton")]
class AltchaService
{
    public function __construct(
        protected string $hmac,
        protected string $algorithm,
        protected int $minNumber,
        protected int $maxNumber,
        protected int $expires,
        protected int $saltLength
    )
    {}

    /**
     * @throws InvalidConfigurationException
     * @throws \DateMalformedIntervalStringException
     * @throws \Random\RandomException
     */
    public function createChallenge(): array
    {
        if (empty($this->hmac)) {
            throw new InvalidConfigurationException('The setting Networkteam.Flow.Altcha.challenge.hmac must be set.', 1744199956);
        }

        $altcha = new Altcha($this->hmac);
        $options = new ChallengeOptions(
            Algorithm::tryFrom($this->algorithm),
            $this->maxNumber,
            $this->getExpiresDate($this->expires),
            [],
            $this->saltLength
        );
        $challenge = $altcha->createChallenge($options);

        return [
            'algorithm' => $challenge->algorithm,
            'challenge' => $challenge->challenge,
            'number' => random_int($this->minNumber, $this->maxNumber),
            'salt' => $challenge->salt,
            'signature' => $challenge->signature,
        ];
    }

    /**
     * @param string $payload
     * @return bool
     */
    public function validate(string $payload): bool
    {
        $altcha = new Altcha($this->hmac);
        return $altcha->verifySolution($payload);
    }

    public function getExpiresDate(int $secondsFromNow): \DateTimeImmutable
    {
        return (new \DateTimeImmutable())->add(new \DateInterval('PT' . $secondsFromNow . 'S'));
    }

    public function setAlgorithm(string $algorithm): void
    {
        $this->algorithm = $algorithm;
    }

    public function setMinNumber(int $minNumber): void
    {
        $this->minNumber = $minNumber;
    }

    public function setMaxNumber(int $maxNumber): void
    {
        $this->maxNumber = $maxNumber;
    }

    public function setExpires(int $expires): void
    {
        $this->expires = $expires;
    }

    public function setSaltLength(int $saltLength): void
    {
        $this->saltLength = $saltLength;
    }
}