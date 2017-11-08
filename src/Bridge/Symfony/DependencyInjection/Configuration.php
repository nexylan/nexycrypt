<?php

namespace Nexy\NexyCrypt\Bridge\Symfony\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * @author Sullivan Senechal <soullivaneuh@gmail.com>
 */
final class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('nexy_crypt');

        $rootNode
            ->children()
                ->scalarNode('private_key_path')->defaultNull()->end()
                ->scalarNode('endpoint')->defaultNull()->end()
                ->arrayNode('http')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('client')->defaultValue('httplug.client.default')->end()
                    ->end()
                ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
