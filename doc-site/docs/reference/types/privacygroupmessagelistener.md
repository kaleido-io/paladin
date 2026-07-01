---
title: PrivacyGroupMessageListener
---
{% include-markdown "./_includes/privacygroupmessagelistener_description.md" %}

### Example

```json
{
    "created": 0,
    "name": "",
    "filters": {},
    "options": {}
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `created` | Time the listener was created | [`Timestamp`](simpletypes.md#timestamp) |
| `name` | Unique name for the message listener | `string` |
| `started` | If the listener is started - can be set to false to disable delivery server-side | `bool` |
| `filters` | Filters to apply to messages | [`PrivacyGroupMessageListenerFilters`](privacygroupmessagelistenerinput.md#privacygroupmessagelistenerfilters) |
| `options` | Options for the message listener | [`PrivacyGroupMessageListenerOptions`](privacygroupmessagelistenerinput.md#privacygroupmessagelisteneroptions) |

