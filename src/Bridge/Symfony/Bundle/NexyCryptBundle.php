<?php

namespace Nexy\NexyCrypt\Bridge\Symfony\Bundle;

use Nexy\NexyCrypt\Bridge\Symfony\DependencyInjection\NexyCryptExtension;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
final class NexyCryptBundle extends Bundle
{
    /**
     * {@inheritdoc}
     */
    protected function getContainerExtensionClass()
    {
        return NexyCryptExtension::class;
    }
}
