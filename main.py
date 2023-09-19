import logging
import os
from datetime import datetime
from typing import TextIO
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import requests as requests
from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization

psd2_client_certs = "psd2-client-certs.crt"


def __config() -> dict:
    """
    Configuration for the download with some static data

    :return: dictionary with configuration data
    """
    return {
        'api_url': 'https://eidas.ec.europa.eu/efda/tl-browser',
        'uri_etsi': '{http://uri.etsi.org/02231/v2#}',
        'svc_granted': 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
        'svc_qc_ca': 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
        'svc_website_auth': 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication',
        'certificate_algorithm_id': 'RSA'
    }


def __download_and_save_certificates() -> None:
    """
    Download and save certificates from ec.europa.eu

    :return: None
    """
    countries_list = __countries_list_from_api()

    with open(psd2_client_certs, 'w') as ca_handler:
        for country in countries_list:
            xml_country_data = __download_country_data_as_xml(country)
            trust_svc_provider_list = __get_trust_svc_provider_list(xml_country_data)
            if trust_svc_provider_list is not None:
                __extract_trust_svc_provider_list(trust_svc_provider_list, ca_handler)


def __countries_list_from_api() -> []:
    """
    Download the country list from ec.europa.eu country list API

    :return: result of request with countries
    """
    return requests.get(f"{__config().get('api_url')}/api/v1/search/countries_list").json()


def __download_country_data_as_xml(country: dict) -> ElementTree:
    """
    Download the list of countries from ec.europe.eu and return the XML Element tree.

    :param country: country element from search API
    :return: XML Element Tree of this country
    """
    logging.info(f"Downloading certificates for [{country['countryName']}]")
    data_xml = requests.get(f"{__config().get('api_url')}/api/v1/browser/download/{country['countryCode']}").content
    return ElementTree.fromstring(data_xml)


def __get_trust_svc_provider_list(xml_data: 'Element') -> 'list[Element]':
    """
    Returns all TrustServiceProvider from the TrustServiceProviderList

    :param xml_data:
    :return:
    """
    tsp_svc_list = xml_data\
        .find(__xml_element_full_name('TrustServiceProviderList'))
    if tsp_svc_list is not None:
        return tsp_svc_list\
            .findall(__xml_element_full_name('TrustServiceProvider'))


def __extract_trust_svc_provider_list(trust_svc_provider_list: 'list[Element]', ca_handler: 'TextIO') -> 'None':
    """
    Extract all TSP Services from TSPServices.TSPService element

    :param trust_svc_provider_list: list of TSP services
    :param ca_handler: file wrapper for storing data
    :return: None
    """
    for tsp in trust_svc_provider_list:
        tsp_name = tsp\
            .find(__xml_element_full_name('TSPInformation'))\
            .find(__xml_element_full_name('TSPName'))\
            .find(__xml_element_full_name('Name'))\
            .text
        logging.debug(f'  -> Processing TSP Name: {tsp_name}')
        tsp_services = tsp\
            .find(__xml_element_full_name('TSPServices'))\
            .findall(__xml_element_full_name('TSPService'))

        __extract_service(tsp_services, ca_handler)


def __extract_service(tsp_list, ca_handler: TextIO):
    for tsp in tsp_list:
        tsp_name = __extract_trst_svc_prvdr_name(tsp)
        tsp_status = __extract_trst_svc_prvdr_status(tsp)
        tsp_type_id = __extract_trst_svc_prvdr_type_id(tsp)

        if __has_granted_svc_and_ca(tsp_status, tsp_type_id):
            try:
                svc_info_url_list = __extract_additional_service_info_urls(tsp)
            except AttributeError:
                raise

            if __config().get('svc_website_auth') in svc_info_url_list:
                digital_ids = __extract_digital_ids(tsp)
                __save_certificate(tsp_name, digital_ids, ca_handler)


def __extract_trst_svc_prvdr_name(tsp_svc: Element) -> str:
    """
    Extract Name from ServiceInformation.ServiceName.Name

    :param tsp_svc: XML Element of trusted service
    :return: name of the service
    """
    return tsp_svc\
        .find(__xml_element_full_name('ServiceInformation'))\
        .find(__xml_element_full_name('ServiceName'))\
        .find(__xml_element_full_name('Name'))\
        .text


def __extract_trst_svc_prvdr_status(tsp_svc: Element) -> str:
    """
    Extraxt Service Status from ServiceInformation.ServiceStatus

    :param tsp_svc: trusted service provider service XML element
    :return: URL of the ServiceStatus element
    """
    return tsp_svc\
        .find(__xml_element_full_name('ServiceInformation'))\
        .find(__xml_element_full_name('ServiceStatus'))\
        .text


def __extract_trst_svc_prvdr_type_id(tsp_svc: Element) -> str:
    """
    Extract Service Type Identifier from ServiceInformation.ServiceTypeIdentifier

    :param tsp_svc: trusted service provider service XML element
    :return: URL of the ServiceTypeIdentifier element
    """
    return tsp_svc\
        .find(__xml_element_full_name('ServiceInformation'))\
        .find(__xml_element_full_name('ServiceTypeIdentifier'))\
        .text


def __extract_additional_service_info_urls(tsp_svc: 'Element') -> 'list[str]':
    """
    Extraxt the additional service URLs as a proper list

    :param tsp_svc: trusted service provider service XML element
    :return: List of URIs from Additional Service Information
    """
    svc_info_url_list = []
    try:
        tsp_service_information = tsp_svc\
            .find(__xml_element_full_name('ServiceInformation'))
        tsp_service_information_extensions = tsp_service_information\
            .find(__xml_element_full_name('ServiceInformationExtensions'))
        tsp_service_extensions = tsp_service_information_extensions\
            .findall(__xml_element_full_name('Extension'))

        for extension in tsp_service_extensions:
            tsp_additional_service_info = extension\
                .find(__xml_element_full_name('AdditionalServiceInformation'))
            if tsp_additional_service_info:
                tsp_additional_service_info_url = tsp_additional_service_info\
                    .find(__xml_element_full_name('URI'))\
                    .text
                if tsp_additional_service_info_url not in svc_info_url_list:
                    svc_info_url_list.append(tsp_additional_service_info_url)
    except AttributeError as ae:
        logging.error("Unable to extract list of URLs of trusted service(s)", ae)
        raise

    return svc_info_url_list


def __extract_digital_ids(tsp_svc: 'Element') -> 'list[Element]':
    """
    Extract DigitalID from ServiceInformation.ServiceDigitalIdentity

    :param tsp_svc: trusted service provider service XML element
    :return: list of elements with the DigitalId
    """
    return tsp_svc \
        .find(__xml_element_full_name('ServiceInformation')) \
        .find(__xml_element_full_name('ServiceDigitalIdentity')) \
        .findall(__xml_element_full_name('DigitalId'))


def __save_certificate(tsp_name: str, digital_ids: 'list[Element]', ca_handler: 'TextIO') -> 'None':
    for digital_id in digital_ids:
        certificates = digital_id.findall(__xml_element_full_name('X509Certificate'))
        for certificate in certificates:
            certificate_pem = f"-----BEGIN CERTIFICATE-----\n{certificate.text}\n-----END CERTIFICATE-----"
            try:
                certificate_details = x509.load_pem_x509_certificate(
                    certificate_pem.encode(),
                    backends.default_backend()
                )
                if datetime.now() < certificate_details.not_valid_after:
                    if __config().get('certificate_algorithm_id') in str(certificate_details.signature_algorithm_oid):
                        logging.info(f' -> Service name : {tsp_name}')
                        logging.info(f' -> Serial number: {str(certificate_details.serial_number)}')
                        logging.info(f' -> Valid until  : {str(certificate_details.not_valid_after)}')
                        decoded_certificate = certificate_details.public_bytes(serialization.Encoding.PEM).decode()
                        ca_handler.write(decoded_certificate)
            except ValueError:
                pass


def __has_granted_svc_and_ca(tsp_status: str, tsp_type_id: str) -> bool:
    """
    Check if TSP element has a granted status and a qc ca available.

    :param tsp_status: status URL of the trusted service provider
    :param tsp_type_id: Type ID of the trusted service provider
    :return: true = all data available or false = provider not supported
    """
    return __config().get('svc_granted') == tsp_status and __config().get('svc_qc_ca') == tsp_type_id


def __xml_element_full_name(name: str) -> str:
    """
    Create the full name inclusive the namespace of an XML element.

    :param name: name of the element
    :return: full name with namespace and element
    """
    return f'{__config().get("uri_etsi")}{name}'


def __remove_old_certs() -> None:
    """
    Remove old certificates if exists

    :return: None
    """
    if os.path.exists(psd2_client_certs):
        os.remove(psd2_client_certs)


def run() -> None:
    """
    Run method to be able to test without importing main()

    :return: None
    """
    logging.basicConfig(level=logging.INFO)
    __remove_old_certs()
    __download_and_save_certificates()


def main():
    run()


if __name__ == '__main__':
    main()
