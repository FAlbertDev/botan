/*
* DN_UB maps: Upper bounds on the length of DN strings
*
* This file was automatically generated by ./src/scripts/dev_tools/gen_oids.py on 2023-02-22
*
* All manual edits to this file will be lost. Edit the script
* then regenerate this source file.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>
#include <botan/asn1_obj.h>
#include <map>

namespace Botan {

namespace {

/**
 * Upper bounds for the length of distinguished name fields as given in RFC 5280, Appendix A.
 * Only OIDS recognized by botan are considered, so far.
 * Maps OID string representations instead of human readable strings in order
 * to avoid an additional lookup.
 */
const std::map<OID, size_t> DN_UB =
   {
   { OID({2,5,4,10}), 64 },      // X520.Organization
   { OID({2,5,4,11}), 64 },      // X520.OrganizationalUnit
   { OID({2,5,4,12}), 64 },      // X520.Title
   { OID({2,5,4,3}), 64 },       // X520.CommonName
   { OID({2,5,4,4}), 40 },       // X520.Surname
   { OID({2,5,4,42}), 32768 },   // X520.GivenName
   { OID({2,5,4,43}), 32768 },   // X520.Initials
   { OID({2,5,4,44}), 32768 },   // X520.GenerationalQualifier
   { OID({2,5,4,46}), 64 },      // X520.DNQualifier
   { OID({2,5,4,5}), 64 },       // X520.SerialNumber
   { OID({2,5,4,6}), 3 },        // X520.Country
   { OID({2,5,4,65}), 128 },     // X520.Pseudonym
   { OID({2,5,4,7}), 128 },      // X520.Locality
   { OID({2,5,4,8}), 128 },      // X520.State
   { OID({2,5,4,9}), 128 }       // X520.StreetAddress
   };

}

//static
size_t X509_DN::lookup_ub(const OID& oid)
   {
   auto ub_entry = DN_UB.find(oid);
   if(ub_entry != DN_UB.end())
      {
      return ub_entry->second;
      }
   else
      {
      return 0;
      }
   }
}

