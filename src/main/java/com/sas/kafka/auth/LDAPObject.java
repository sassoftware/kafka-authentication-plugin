/**
 * Copyright © 2024, SAS Institute Inc., Cary, NC, USA.  All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sas.kafka.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Information about an LDAP object.
 */
public class LDAPObject extends Object {


    /** The LDAP common name (CN) */
    private String commonName = null;

    /** The LDAP organizational units */
    private List<String> organizationalUnits = null;

    /** The LDAP domain components */
    private List<String> domainComponents = new ArrayList<String>();


    /**
     * Construct an empty object.
     */
    public LDAPObject() {
    }

    /**
     * Set the LDAP common name for the object.
     *
     * @param  name  Common name
     */
    public void setCommonName(String name) {
        this.commonName = name;
    }

    /**
     * Return the LDAP common name for the object.
     *
     * @return  Common name
     */
    public String getCommonName() {
        return commonName;
    }

    /**
     * Return true if the common name is set.
     *
     * @return TRUE if the common name is set
     */
    public boolean hasCommonName() {
        return ((commonName != null) && (commonName.trim().length() > 0));
    }

    /**
     * Set the list of LDAP organizational unit names for the object.
     *
     * @param  list  organizational unit name
     */
    public void setOrganizationalUnits(Collection<String> list) {
        organizationalUnits = new ArrayList<String>(list);
    }

    /**
     * Return the list of LDAP organizational unit names for the object.
     *
     * @return  list of organizational unit names
     */
    public Collection<String> getOrganizationalUnits() {
        return organizationalUnits;
    }

    /**
     * Return true if there are any organizational units.
     *
     * @return  TRUE if organizational units exist
     */
    public boolean hasOrganizationalUnits() {
        return ((organizationalUnits != null) && (organizationalUnits.size() > 0));
    }

    /**
     * Add an organizational unit to the list.
     *
     * @param  org  Organizational unit name
     */
    public void addOrganizationalUnit(String org) {
        // Make sure the list has been initialized
        if (organizationalUnits == null) {
            organizationalUnits = new ArrayList<String>();
        }

        // Add the org unit to the list if it does not already exist
        if (!organizationalUnits.contains(org)) {
            organizationalUnits.add(org);
        }
    }

    /**
     * Set the list of domain components for the object.
     *
     * @param  list   Domain components
     */
    public void setDomainComponents(Collection<String> list) {
        domainComponents = new ArrayList<String>(list);
    }

    /**
     * Return the list of domain components for the object, or null if none are defined.
     *
     * @return List of domain components
     */
    public Collection<String> getDomainComponents() {
        return domainComponents;
    }

    /**
     * Return true if there are any organizational units.
     *
     * @return  TRUE if organizational units exist
     */
    public boolean hasDomainComponents() {
        return ((domainComponents != null) && (domainComponents.size() > 0));
    }

    /**
     * Add a domain component to the list.
     *
     * @param  component  Domain component
     */
    public void addDomainComponent(String component) {
        // Make sure the list has been initialized
        if (domainComponents == null) {
            domainComponents = new ArrayList<String>();
        }

        // Add the component to the list if it does not already exist
        if (!domainComponents.contains(component)) {
            domainComponents.add(component);
        }
    }

}
