<?php

namespace App\Controller\API;

use App\Entity\Module;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Serializer\Context\Normalizer\ObjectNormalizerContextBuilder;

#[Route('/api')]
class ModuleController extends AbstractController
{
    #[Route('/modules', name: 'app_module')]
    public function index(
        EntityManagerInterface $em,
    ): JsonResponse {

        $modules = $em->getRepository(Module::class)->findAll();

        return $this->json($modules, context: ['groups' => ["show_modules"]]);
    }
}
