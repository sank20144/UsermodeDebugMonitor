# UsermodeDebugMonitor

The application is currently designed to protect itself from debugging. 
In further iterations, the ability to monitor another application for debugging will be added.
This would be in the form of an injectable dll or manually adding a TLS callback to the desired application to call the antidebug module. 

# References

- https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=230d68b2-c80f-4436-9c09-ff84d049da33&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments
- https://github.com/processhacker/processhacker
- https://www.blackhat.com/docs/asia-14/materials/Li/Asia-14-Li-Comprehensive-Virtual-Appliance-Detection.pdf
- https://forum.reverse4you.org/t/topic/403/6
- https://docs.microsoft.com/en-us/windows/win32/dlls/using-thread-local-storage-in-a-dynamic-link-library
