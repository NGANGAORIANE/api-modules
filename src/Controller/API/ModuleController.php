<?php

namespace App\Controller\API;

use App\Entity\Module;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Serializer\SerializerInterface;

#[Route('/api')]
class ModuleController extends AbstractController
{
    #[Route('/modules', name: 'app_module')]
    public function index(EntityManagerInterface $em): JsonResponse
    {
        $modules = $em->getRepository(Module::class)->findAll();

        $prepare = [];
        foreach ($modules as $module) {
            $prepare[] = ["title" => $module->getTitle(), "description" => $module->getDescription()];
        }

        return $this->json([
            'firstName' => $this->getUser()->getFirstname(),
            'modules' =>$prepare
        ]);
    }
}
