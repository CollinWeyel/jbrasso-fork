# A fork of jbra oauth sso plugin for Joomla 5

This is an fork of jbrasso to make it working with Joomla 5.x.. Nothing fancy really.

## Download

You can just download this repo as a zip file from the `<> Code` button above or click here [main.zip](https://github.com/CollinWeyel/jbrasso-fork/archive/refs/heads/main.zip).

## Installation

Just upload the previous downloaded zip file in the joomla extension manager.

## Usage

Just configure the listed parameters in the plugin configuration and set the access level to `Public`. Then everything should work.

## Credits

Thanks to [Ioannis Brailas](https://github.com/jbrailas) for the original plugin.

## License

JbraSSO-Fork is licensed under GNU Lesser General Public License v3.0 (LGPL-3.0) [LGPLv3](./LICENSE.md).

## Notes

I'm not saying that this code is perfect, but it works. The goal was just to get a MVP for basic authentication. I'm not a joomla or php developer. Improvements are welcome.

Another thing to note is that this plugin is that the [sql-Directory](./sql) is currently useless. The same goes for the `<sql>` section in [jbrasso.xml](./jbra_sso.xml). I don't know if this worked in a earlier version of Joomla, but it doesn't work in Joomla 5. The required `<administrator>` block is not valid for extensions of the type `plugin`. The same goes for the `<sql>` part. Therefore the required database table gets createt through an call in the constructor of the plugin. This means, that I'm not sure if the table gets deleted, when the plugin gets uninstalled. I would expect that the table gets deleted as I get an error when Joomla can't find the file [sql/uninstall.mysql.sql](./sql/uninstall.mysql.sql), but I'm not sure.
