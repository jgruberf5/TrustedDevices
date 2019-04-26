# TrustedDevices
**iControlLX extension to make device trusts declarative**

TMOS devices have the ability to *trust* each other to perform requests under the *Administrator* role. Device trusts are used in *TMOS* to synchronize configuration data and query device status. Trust can also be use to authorize iControl REST requests to query or provision a device.

Trusts are established by the creation of a device group and the exchange of device certificates. The initial exchange of certificates requires a remote device's *Administrator* role credentials, but once the certificates are exchanged, subsequent request can be signed using the certificate verse exchanging credentials for access tokens. Within an orchestration application, the ability to utilize device trusts provides separation of concerns for various application services. A separate application request can establish the trust, using supplied credentials, and then other application requests can utilize the trust without providing credentials.

The iControl REST requests to manage device groups, devices, and certificates can be difficult to understand. This is where our iControlLX extension plays its part. This extension makes the trusting of devices declarative.

## Building the Extension ##

The repository includes the ability to simply run 

`npm run-script build` 

in the repository root folder. In order for this run-script to work, you will need to be on a linux workstation with the `rpmbuild` utility installed.

Alternatively rpm builds can be downloaded from the releases tab on github.

## Installing the Extension ##

The installation instructions for iControlLX rpm packages are found here:

[Installing iControlLX Extensions](https://clouddocs.f5.com/products/iapp/iapp-lx/docker-1_0_4/icontrollx_pacakges/working_with_icontrollx_packages.html)

This extension has been tested on TMOS version 13.1.1 and the [API Service Gateway](https://hub.docker.com/r/f5devcentral/f5-api-services-gateway/) container.

## Requirements on TMOS Devices ##

Due to limitations imposed by TMOS common interface management, in order for devices to participate in a trust, each TMOS device **must** have a `configsync-ip` non-floating SelfIP defined. Without a `configsync-ip` properly configured, a device's certificate can not be discovered by its peer and the trust can not be established.

Configuring a configsync-ip for your version of TMOS is documented in the TMOS operations guides. The `tmsh` shell command to set the `configsync-ip` is as follows:

`tmsh modify cm device [device_name] configsync-ip [selfipaddress]`

You must provision this before attempting to add device trusts with this extension.

## Establishing a Trust ##

This extension extends the iControl REST URI namespace at:

`/mgmt/shared/TrustedDevices`

Being a declarative interface, this extension support `GET` and `POST` methods only. 

#### Query Active Trusts ####

Making an iControl REST `GET` request against the `/mgmt/shared/TrustedDevices` URI endpoint will yield a listing of established device trust.

`GET` `/mgmt/shared/TrustedDevices`

Response

```
{
    "devices": [
        {
            "targetUUID": "7390b3b8-7682-4554-83e5-764e4f26703c",
            "targetHost": "172.13.1.107",
            "targetPort": 443,
            "state": "ACTIVE",
            "targetHostname": "bigip1.openstack.local",
            "targetVersion": "13.1.1"
            "targetRESTVersion": "13.1.1-0.0.4",
            "available": true,
            "lastValidated": "2019-03-28T18:38:00.053Z"
        },
        {
            "targetUUID": "e634cbdc-8690-4f03-acdc-219197788fc1",
            "targetHost": "172.13.1.108",
            "targetPort": 443,
            "state": "ACTIVE",
            "targetHostname": "bigip2.openstack.local",
            "targetVersion": "13.1.1"
            "targetRESTVersion": "13.1.1-0.0.4",
            "available": true,
            "lastValidated": "2019-03-28T18:38:01.018Z"
        },
        {
            "targetUUID": "eee963cc-6dcb-4f02-a640-c4ef5842f9f8",
            "targetHost": "172.13.1.109",
            "targetPort": 443,
            "state": "ACTIVE",
            "targetHostname": "bigip3.openstack.local",
            "targetVersion": "13.1.1"
            "targetRESTVersion": "13.1.1-0.0.4",
            "available": true,
            "lastValidated": "2019-03-28T18:38:01.026Z"
        },
        {
            "targetUUID": "85651c46-f0ae-479e-95a8-3ebe1795320d",
            "targetHost": "172.13.1.110",
            "targetPort": 443,
            "state": "ACTIVE",
            "targetHostname": "bigip4.openstack.local",
            "targetVersion": "13.1.1"
            "targetRESTVersion": "13.1.1-0.0.4",
            "available": true,
            "lastValidated": "2019-03-28T18:38:02.001Z"
        }
    ]
}
```

#### Declaring Trusts ####

Being a declarative interface, issuing a `POST` request to the `/mgmt/shared/TrustedDevices` iControl REST URI endpoint will either cause the creation or deletion of device trust. You must declare all desired trusts.

The simplest example would be an empty declaration, which would remove all trusts.


`POST` `/mgmt/shared/TrustedDevices`

Body
```
{
    "devices": []
}
```

Response

```
{
    "devices": [
        
    ]
}
```

To add a trust, trusted devices must be declared. When declaring a device to trust there are four required attributes:

```
{
    "targetHost": [an iControl REST host]
    "targetPort": [an iControl REST TCP port]
    "targetUsername": [Administrator role username]
    "targetPassphrase": [password for targetUsername]
}
```
Creating a trust is the only time TMOS credentials are needed. The credentials are write only attributes and not stored.

To create a trust to two BIG-IPs, one at `172.13.1.107` and another at `172.13.1.108` declare them as follows:

`POST` `/mgmt/shared/TrustedDevices`

Body
```
{
    "devices": [
        {
            "targetHost": "172.13.1.107",
            "targetPort": 443,
            "targetUsername": "admin",
            "targetPassphrase": "admin"
        },
        {
            "targetHost": "172.13.1.108",
            "targetPort": 443,
            "targetUsername": "admin",
            "targetPassphrase": "admin"
        }
    ]
}
```

Response
```
{
    "devices": [
        {
            "targetUUID": "7390b3b8-7682-4554-83e5-764e4f26703c",
            "targetHost": "172.13.1.107",
            "targetPort": 443,
            "state": "CREATED",
            "targetHostname": "bigip1.openstack.local",
            "targetVersion": "13.1.1",
            "targetRESTVersion": "13.1.1-0.0.4",
            "available": false
        },
        {
            "targetUUID": "e634cbdc-8690-4f03-acdc-219197788fc1",
            "targetHost": "172.13.1.108",
            "targetPort": 443,
            "state": "CREATED",
            "targetHostname": "bigip2.openstack.local",
            "targetVersion": "13.1.1",
            "targetRESTVersion": "13.1.1-0.0.4",
            "available": false
        }
    ]
}
```

The response returns the devices and a read only attribute `state`. The devices can then be queried using a `GET` request to see any changes in the trust `state`. Once the `state` transitions to `ACTIVE`, the trust can be used.

If there are any issues creating the trust, the `state` will become `ERROR` or `UNDISCOVERED`. If your device `state` transitions to either of these states, check both `/var/log/restjavad.0.log` and `/var/log/restnoded/restnoded.log` on the device where this extension is installed. Once the issue called out in the log has been corrected, you can simply redeclare the trust.

To remove a trust, simply remove it from the declaration. For device trust which `state` reaches `ACTIVE` that you which to retain, you do not need to supply the `targetUsername` or `targetPassphrase` attribute again.

Here is an example which would remove the `172.13.1.108` device trust, but retain the `172.13.1.107` device trust.

`POST` `/mgmt/shared/TrustedDevices`

Body
```
{
    "devices": [
        {
            "targetHost": "172.13.1.107",
            "targetPort": 443
        }
    ]
}
```

Response
```
{
    "devices": [
        {
            "targetUUID": "7390b3b8-7682-4554-83e5-764e4f26703c",
            "targetHost": "172.13.1.107",
            "targetPort": 443,
            "state": "ACTIVE",
            "targetHostname": "bigip2.openstack.local",
            "targetVersion": "13.1.1",
            "targetRESTVersion": "13.1.1-0.0.4",
            "available": false
        }
    ]
}

```

You can append devices to the existing trusts by using the `PUT` method using the same declaration format, but supplying only the devices you want to append trusts. The `PUT` method will only return the devices trusts being appended, it will not return other existing devices.

To add a trust for the device at `172.13.1.108` with an existing trust at `172.13.1.107` declare them as follows:

`PUT` `/mgmt/shared/TrustedDevices`

Body
```
{
    "devices": [
        {
            "targetHost": "172.13.1.108",
            "targetPort": 443,
            "targetUsername": "admin",
            "targetPassphrase": "admin"
        }
    ]
}
```

Response
```
{
    "devices": [
        {
            "targetUUID": "e634cbdc-8690-4f03-acdc-219197788fc1",
            "targetHost": "172.13.1.108",
            "targetPort": 443,
            "state": "CREATED",
            "targetHostname": "bigip2.openstack.local",
            "targetVersion": "13.1.1",
            "targetRESTVersion": "13.1.1-0.0.4",
            "available": false
        }
    ]
}
```

You can delete specific devices from the trusts by using the `DELETE` method specifying the device by either including the `targetUUID` as the last path element, or indicating the `targetHost` as a query parameter. The `DELETE` method will return only the device being deleted, now in the `DELETING` state. If the requested device is not already trusted, it will return an empty list rather then an error. 

To delete all trusts, use the `POST` method with an empty device declaration.

To delete only the device trust for the device with the `targetUUID` of `e634cbdc-8690-4f03-acdc-219197788fc1`:

`DELETE` `/mgmt/shared/TrustedDevices/e634cbdc-8690-4f03-acdc-219197788fc1`

Response
```
{
    "devices": [
        {
            "targetUUID": "e634cbdc-8690-4f03-acdc-219197788fc1",
            "targetHost": "172.13.1.108",
            "targetPort": 443,
            "state": "DELETING",
            "targetHostname": "bigip2.openstack.local",
            "targetVersion": "13.1.1",
            "targetRESTVersion": "13.1.1-0.0.4",
            "available": false
        }
    ]
}
```

**Detecting Trust Failures**

TrustedDevices polls all declared devices and attempts to make an iControl REST call through the trust every 10 seconds. If the API call succeeds, the `available` attribute for the device is set to `true`, and a `lastValidated` attribute is populated showing the last time trust validation occurred. If the API call fails, the `available` attribute for the device is set to `false`, and two new attributes are added, `failedSince` and `failedReason`. The `failedSince` attribute will show the time of the first of any successive failures and the `failedReason` will show the reason for the last recorded failure.

```
{
    "devices": [
        {
            "targetUUID": "330ad1e8-4780-46f0-bc73-e311367b989f",
            "targetHost": "172.13.1.120",
            "targetPort": 443,
            "state": "ACTIVE",
            "targetHostname": "test-11-5-6.sample.openstack.f5se.com",
            "targetVersion": "11.5.6",
            "targetRESTVersion": "13.1.0-0.0.6087",
            "available": false,
            "failedSince": "2019-03-28T19:10:11.768Z",
            "failedReason": "connect EHOSTUNREACH 172.13.1.120:443"
        }
    ]
}
```