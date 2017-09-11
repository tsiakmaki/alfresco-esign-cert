package es.keensoft.alfresco.behaviour;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.node.NodeServicePolicies;
import org.alfresco.repo.policy.Behaviour.NotificationFrequency;
import org.alfresco.repo.policy.JavaBehaviour;
import org.alfresco.repo.policy.PolicyComponent;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.repository.AssociationRef;
import org.alfresco.service.cmr.repository.ChildAssociationRef;
import org.alfresco.service.cmr.repository.ContentData;
import org.alfresco.service.cmr.repository.ContentReader;
import org.alfresco.service.cmr.repository.ContentService;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.version.VersionService;
import org.alfresco.service.namespace.QName;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfPKCS7;
import com.itextpdf.text.pdf.PdfReader;

import es.keensoft.alfresco.model.SignModel;

public class CustomBehaviour implements 
    NodeServicePolicies.OnDeleteAssociationPolicy, 
    NodeServicePolicies.OnCreateNodePolicy {
	
	private static Log logger = LogFactory.getLog(CustomBehaviour.class);
	
	private PolicyComponent policyComponent;
	private NodeService nodeService;
	private VersionService versionService;
	private ContentService contentService;
	
	private static final String PADES = "PAdES";
	
	public void init() {
		policyComponent.bindAssociationBehaviour(NodeServicePolicies.OnDeleteAssociationPolicy.QNAME, 
				SignModel.ASPECT_SIGNATURE, new JavaBehaviour(this, "onDeleteAssociation", 
				NotificationFrequency.TRANSACTION_COMMIT));
		policyComponent.bindClassBehaviour(
		        NodeServicePolicies.OnCreateNodePolicy.QNAME,
		        ContentModel.TYPE_CONTENT,
		        new JavaBehaviour(this, "onCreateNode", NotificationFrequency.TRANSACTION_COMMIT)
		    );
	}
	

	@Override
	public void onCreateNode(ChildAssociationRef childNodeRef) {
		
		final NodeRef node = childNodeRef.getChildRef();
		
		if (!nodeService.exists(node)) {
            return;
		}

		// if onCreateNode the document hasSignedAspect, the document has not been 
		// uploaded by a user. It has been copied/ moved inside alfresco. 
		boolean hasSignedAspect = nodeService.hasAspect(node, SignModel.ASPECT_SIGNED);
		
		if (hasSignedAspect) {
			
			List<ChildAssociationRef> assocs = nodeService.getChildAssocs(node);
			
			// remove every signature that had been associated in the past 
			for(ChildAssociationRef a : assocs) {
				
				NodeRef signatureNodeRef = a.getChildRef();
				
				nodeService.removeAssociation(node, signatureNodeRef, SignModel.ASSOC_SIGNATURE);
				logger.info("DeleteAssociation: from=" + node.getId() + " to="  + signatureNodeRef.getId() + " model=" + SignModel.ASSOC_SIGNATURE);
				
				nodeService.removeAssociation(signatureNodeRef, node, SignModel.ASSOC_DOC);
				logger.info("DeleteAssociation: from=" + signatureNodeRef.getId() + " to="  + node.getId() + " model=" + SignModel.ASSOC_DOC);
				
				nodeService.deleteNode(signatureNodeRef);
				logger.info("deleteNode: nodeRef=" + signatureNodeRef);
			}
			
			nodeService.removeAspect(node, SignModel.ASPECT_SIGNED);
			logger.info("removeAspect: to=" + node.getId());
		}
		
		// if the new document is pdf, and contains digital signature(s), 
		// create (for each signature) a empty document to represent the digital signature
		// create associations between the document and the signature (back and forth)
		// add the sign aspect to the document 
		// we run them as admin to avoid child association exceptions, because of our alfresco sites settings and permittions 
		ContentData contentData = (ContentData) nodeService.getProperty(node, ContentModel.PROP_CONTENT);
		// Do this check only if the uploaded document is a PDF
		if (contentData != null && contentData.getMimetype().equalsIgnoreCase("application/pdf")) {
			ArrayList<Map<QName, Serializable>> signatures = getDigitalSignatures(node);

			if(signatures != null) {
				// for each signature found in the pdf file
				for(final Map<QName, Serializable> aspectProperties : signatures) {
					String originalFileName = nodeService.getProperty(node, ContentModel.PROP_NAME).toString();
					final String signatureFileName = FilenameUtils.getBaseName(originalFileName) + "-" 
					+ System.currentTimeMillis() + "-" + PADES;
					
					// run as admin 
					AuthenticationUtil.runAsSystem(new AuthenticationUtil.RunAsWork<Object>() {
					      public Object doWork() throws Exception {
					    	// Creating a node reference without type (no content and no folder): remains invisible for Share
							NodeRef signatureNodeRef = nodeService.createNode(
									nodeService.getPrimaryParent(node).getParentRef(),
									ContentModel.ASSOC_CONTAINS, 
									QName.createQName(signatureFileName), 
									ContentModel.TYPE_CMOBJECT).getChildRef();
							// associate document with signature
							nodeService.createAssociation(node, signatureNodeRef, SignModel.ASSOC_SIGNATURE);
							logger.info("CreateAssociation: from=" + node.getId() + " to="  + signatureNodeRef.getId() + " model=" + SignModel.ASSOC_SIGNATURE);
							// associate signature with document
							nodeService.createAssociation(signatureNodeRef, node, SignModel.ASSOC_DOC);
							logger.info("CreateAssociation: from=" + signatureNodeRef.getId() + " to="  + node.getId() + " model=" + SignModel.ASSOC_DOC);
							// add aspect 
						    aspectProperties.put(SignModel.PROP_FORMAT, PADES);
							nodeService.addAspect(signatureNodeRef, SignModel.ASPECT_SIGNATURE, aspectProperties);
							logger.info("addAspect: to=" + signatureNodeRef.getId());

							return null;
					      }
					});
				}
			}
		}
	}

	@Override
	public void onDeleteAssociation(AssociationRef nodeAssocRef) {
		if (nodeService.exists(nodeAssocRef.getTargetRef())) {
		    nodeService.removeAspect(nodeAssocRef.getTargetRef(), SignModel.ASPECT_SIGNED);
		}
	}
	
	
	public ArrayList<Map<QName, Serializable>> getDigitalSignatures(NodeRef node) {
		
		InputStream is = null;
		
		try {
		
			ContentReader contentReader = contentService.getReader(node, ContentModel.PROP_CONTENT);
			is = contentReader.getContentInputStream();
			
			// For SHA-256 and upper
			loadBCProvider();
			
			PdfReader reader = new PdfReader(is);
	        AcroFields af = reader.getAcroFields();
	        ArrayList<String> names = af.getSignatureNames();
	        if(names == null || names.isEmpty()) return null;
	        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
	        ks.load(null, null);
	        ArrayList<Map<QName, Serializable>> aspects = new ArrayList<Map<QName, Serializable>>();
	        for (String name : names) {
	            PdfPKCS7 pk = af.verifySignature(name);
	            X509Certificate certificate = pk.getSigningCertificate();
	           
	            //Set aspect properties for each signature
	            Map<QName, Serializable> aspectSignatureProperties = new HashMap<QName, Serializable>(); 
	            if (pk.getSignDate() != null) aspectSignatureProperties.put(SignModel.PROP_DATE, pk.getSignDate().getTime());
	    		aspectSignatureProperties.put(SignModel.PROP_CERTIFICATE_PRINCIPAL, certificate.getSubjectX500Principal().toString());
	    	    aspectSignatureProperties.put(SignModel.PROP_CERTIFICATE_SERIAL_NUMBER, certificate.getSerialNumber().toString());
	    	    aspectSignatureProperties.put(SignModel.PROP_CERTIFICATE_NOT_AFTER, certificate.getNotAfter());
	    	    aspectSignatureProperties.put(SignModel.PROP_CERTIFICATE_ISSUER, certificate.getIssuerX500Principal().toString());   
	    	    aspects.add(aspectSignatureProperties);
	        }
	        
	        // As this verification can be included in a massive operation, closing files is required
	        is.close();
	        
			return aspects;
			
		} catch (Exception e) {
			
			// Closing stream (!)
			try {
			    if (is != null) is.close();
			} catch (IOException ioe) {}
			
			// Not every PDF has a signature inside
			logger.warn("No signature found!", e);
			return null;
			
			// WARN: Do not throw this exception up, as it will break WedDAV PDF files uploading 
		}
	}
	
	@SuppressWarnings("rawtypes")
	private void loadBCProvider() {
        try {
            Class c = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            Security.insertProviderAt((Provider)c.newInstance(), 2000);
        } catch(Exception e) {
            // provider is not available
        }		
	}
	
	public PolicyComponent getPolicyComponent() {
		return policyComponent;
	}

	public void setPolicyComponent(PolicyComponent policyComponent) {
		this.policyComponent = policyComponent;
	}

	public NodeService getNodeService() {
		return nodeService;
	}

	public void setNodeService(NodeService nodeService) {
		this.nodeService = nodeService;
	}

	public VersionService getVersionService() {
		return versionService;
	}

	public void setVersionService(VersionService versionService) {
		this.versionService = versionService;
	}
	
	public ContentService getContentService() {
		return contentService;
	}
	
	public void setContentService(ContentService contentService) {
		this.contentService = contentService;
	}


}