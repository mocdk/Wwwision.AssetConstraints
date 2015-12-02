<?php
namespace Wwwision\AssetConstraints\Security\Authorization\Privilege\Doctrine;

use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Security\Authorization\Privilege\Entity\Doctrine\ConditionGenerator as EntityConditionGenerator;
use TYPO3\Flow\Security\Authorization\Privilege\Entity\Doctrine\PropertyConditionGenerator;
use TYPO3\Flow\Security\Authorization\Privilege\Entity\Doctrine\TrueConditionGenerator;
use TYPO3\Flow\Security\Exception;
use TYPO3\Flow\Security\Exception\InvalidPrivilegeException;
use TYPO3\Media\Domain\Model\AssetCollection;
use TYPO3\Neos\Domain\Repository\DomainRepository;
use TYPO3\Neos\Domain\Service\UserService;
use Admhuset\RealEstateWebsites\Domain\Repository\SiteRepository;

/**
 * A SQL condition generator, supporting special SQL constraints for asset collections
 */
class AssetCollectionConditionGenerator extends EntityConditionGenerator
{
    /**
     * @Flow\Inject
     * @var UserService
     */
    protected $userService;

    /**
     * @Flow\Inject
     * @var SiteRepository
     */
    protected $siteRepository;

	/**
	 * @var \TYPO3\Flow\Security\Context
	 * @Flow\Inject
	 */
	protected $securityContext;

	/**
	 * @Flow\Inject
	 * @var DomainRepository
	 */
	protected $domainRepository;

    /**
     * @var string
     */
    protected $entityType = AssetCollection::class;

    /**
     * @param string $entityType
     * @return boolean
     * @throws InvalidPrivilegeException
     */
    public function isType($entityType)
    {
        throw new InvalidPrivilegeException('The isType() operator must not be used in AssectCollection privilege matchers!', 1445941247);
    }

    /**
     * @param string $collectionTitle
     * @return PropertyConditionGenerator
     */
    public function isTitled($collectionTitle)
    {
        $propertyConditionGenerator = new PropertyConditionGenerator('title');
        return $propertyConditionGenerator->equals($collectionTitle);

    }

    /**
     * @return PropertyConditionGenerator
     */
    public function isNotMyAssetCollection()
    {
        $user = $this->userService->getCurrentUser();
        $site = $this->siteRepository->findOneByUser($user);

        $propertyConditionGenerator = new PropertyConditionGenerator('title');

		if ($this->securityContext->hasRole('TYPO3.Neos:Administrator')) {
//			$currentSiteName = $this->domainRepository->findOneByActiveRequest()->getSite()->getName();
			return $propertyConditionGenerator->notEquals('');
		} elseif ($site === NULL) {
			throw new Exception('You do not have access to any sites');
        } else {
			return $propertyConditionGenerator->notEquals($site->getNeosSiteModel()->getName());
        }
    }
}