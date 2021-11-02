/**
 * This library provides all necessary functionality to build, encode and decode a VICAL signed certificate lists.
 * It only provides the technical means to do so; it does not provide any of the system / infrastructure required to build a functional VICAL.
 * The library does support all of the fields defined in ISO/IEC FDIS 18013-5, 2021, 
 * <p>
 * The VICAL consists of two main structures in classes with the same name:
 * <ol>
 * <li>The <code>Vical</code> itself, which contains the meta information about the VICAL</li>
 * <li>The <code>CertificateInfo</code> which contains the meta information about the certificate as well as the certificate itself</li>
 * </ol>
 * These classes both have three internal classes each:
 * <ol>
 * <li>A <code>Builder</code> class which can be used to create or copy and adjust an existing <code>Vical</code> or <code>CertificateInfo</code> instance.  
 * <li>An <code>Encoder</code> class to encode the structures to a CBOR branch</li>
 * <li>A <code>Decoder</code> class to decode the structures from a CBOR branch</li>
 * </ol>
 * <p> 
 * Notes:
 * <ul>
 * <li>All the fields are present and can be retrieved from the structures. The structures themselves are immutable, you will need to use a <code>Builder</code> class to create an new Vical instance from an existing one. For this reason the <code>Vical.Builder</code> class has a copy constructor.</li>
 * <li>The library doesn't contain any functional components; it's a library, not a component. That also means that e.g. the increase of the optional <code>vicalIssueID</code> is not performed automatically.</li>
 * <ul>
 */

package com.android.mdl.appreader.issuerauth.vical;

