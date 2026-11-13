using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

// Stand-ins for the database libraries the queries hooks find by name: the
// same namespaces, type names and members the real ones have, and nothing else.

namespace Microsoft.Data.Sqlite
{
    public sealed class SqliteCommand
    {
        public string CommandText { get; set; } = "";
    }
}

namespace Npgsql
{
    public sealed class NpgsqlCommand
    {
        public string CommandText { get; set; } = "";
    }
}

namespace SiteGoose.Tests
{
    /// <summary>SqlClient's command, as far as the hook reads it.</summary>
    public sealed class FakeSqlCommand
    {
        public string CommandText { get; set; } = "";
    }
}

namespace MongoDB.Bson
{
    public abstract class BsonValue
    {
    }

    public sealed class BsonString : BsonValue
    {
        public BsonString(string value) => Value = value;
        public string Value { get; }
        public override string ToString() => Value;
    }

    public sealed class BsonInt32 : BsonValue
    {
        public BsonInt32(int value) => Value = value;
        public int Value { get; }
        public override string ToString() => Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    public readonly struct BsonElement
    {
        public BsonElement(string name, BsonValue value)
        {
            Name = name;
            Value = value;
        }

        public string Name { get; }
        public BsonValue Value { get; }
    }

    public class BsonDocument : BsonValue, IEnumerable<BsonElement>
    {
        private readonly List<BsonElement> elements = new();

        public void Add(string name, BsonValue value) => elements.Add(new BsonElement(name, value));
        public IEnumerator<BsonElement> GetEnumerator() => elements.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    public class BsonArray : BsonValue, IEnumerable<BsonValue>
    {
        private readonly List<BsonValue> values = new();

        public void Add(BsonValue value) => values.Add(value);
        public IEnumerator<BsonValue> GetEnumerator() => values.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}

namespace MongoDB.Driver.Core.Events
{
    using MongoDB.Bson;

    public readonly struct CommandStartedEvent
    {
        public CommandStartedEvent(string commandName, BsonDocument command, int requestId)
        {
            CommandName = commandName;
            Command = command;
            RequestId = requestId;
        }

        public string CommandName { get; }
        public BsonDocument Command { get; }
        public int RequestId { get; }
    }

    public readonly struct CommandSucceededEvent
    {
        public CommandSucceededEvent(string commandName, int requestId, TimeSpan duration)
        {
            CommandName = commandName;
            RequestId = requestId;
            Duration = duration;
        }

        public string CommandName { get; }
        public int RequestId { get; }
        public TimeSpan Duration { get; }
    }

    public readonly struct CommandFailedEvent
    {
        public CommandFailedEvent(string commandName, int requestId, TimeSpan duration)
        {
            CommandName = commandName;
            RequestId = requestId;
            Duration = duration;
        }

        public string CommandName { get; }
        public int RequestId { get; }
        public TimeSpan Duration { get; }
    }
}

namespace MongoDB.Driver.Core.Configuration
{
    public sealed class ClusterBuilder
    {
        public readonly List<Delegate> Handlers = new();

        public ClusterBuilder Subscribe<TEvent>(Action<TEvent> handler)
        {
            Handlers.Add(handler);
            return this;
        }

        public void Fire<TEvent>(TEvent e)
        {
            foreach (var handler in Handlers.OfType<Action<TEvent>>()) handler(e);
        }
    }
}

namespace MongoDB.Driver
{
    using MongoDB.Driver.Core.Configuration;

    public sealed class MongoClientSettings
    {
        public Action<ClusterBuilder>? ClusterConfigurator { get; set; }
    }
}

namespace StackExchange.Redis.Profiling
{
    public interface IProfiledCommand
    {
        string Command { get; }
        TimeSpan ElapsedTime { get; }
        IProfiledCommand? RetransmissionOf { get; }
    }

    internal sealed class ProfiledCommand : IProfiledCommand
    {
        public string Command { get; init; } = "";
        public TimeSpan ElapsedTime { get; init; }
        public IProfiledCommand? RetransmissionOf { get; init; }
    }

    public readonly struct ProfiledCommandEnumerable : IEnumerable<IProfiledCommand>
    {
        private readonly List<IProfiledCommand> commands;

        internal ProfiledCommandEnumerable(List<IProfiledCommand> commands) => this.commands = commands;
        public IEnumerator<IProfiledCommand> GetEnumerator() => commands.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    public sealed class ProfilingSession
    {
        private List<IProfiledCommand> commands = new();

        public ProfilingSession(object? userToken = null) => UserToken = userToken;

        public object? UserToken { get; }

        internal void Add(IProfiledCommand command)
        {
            lock (this) commands.Add(command);
        }

        public ProfiledCommandEnumerable FinishProfiling()
        {
            lock (this)
            {
                var done = commands;
                commands = new();
                return new ProfiledCommandEnumerable(done);
            }
        }
    }
}

namespace StackExchange.Redis
{
    using StackExchange.Redis.Profiling;

    public sealed class ConnectionMultiplexer
    {
        private Func<ProfilingSession?>? provider;

        public int Registered { get; private set; }

        public void RegisterProfiler(Func<ProfilingSession?> profilingSessionProvider)
        {
            provider = profilingSessionProvider;
            Registered++;
        }

        /// <summary>A command made now and finished after ms, as the multiplexer profiles one.</summary>
        public IProfiledCommand Run(string command, double ms, IProfiledCommand? resentFor = null)
        {
            var done = new ProfiledCommand { Command = command, ElapsedTime = TimeSpan.FromMilliseconds(ms), RetransmissionOf = resentFor };
            provider?.Invoke()?.Add(done);
            return done;
        }
    }
}
