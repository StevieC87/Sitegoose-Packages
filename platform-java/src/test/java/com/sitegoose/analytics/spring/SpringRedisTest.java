package com.sitegoose.analytics.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.sitegoose.analytics.Platform;
import io.lettuce.core.AbstractRedisClient;
import io.lettuce.core.event.command.CommandListener;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

/** The starter puts the command listener on Spring Data Redis's Lettuce client, before it connects. */
class SpringRedisTest {
    @SuppressWarnings("unchecked")
    static List<CommandListener> listeners(AbstractRedisClient client) throws Exception {
        Method method = AbstractRedisClient.class.getDeclaredMethod("getCommandListeners");
        method.setAccessible(true);
        return (List<CommandListener>) method.invoke(client);
    }

    @Test
    void lettuceConnectionFactory() throws Exception {
        LettuceConnectionFactory factory = new LettuceConnectionFactory("127.0.0.1", 6399);
        factory.afterPropertiesSet();
        try {
            AbstractRedisClient client = factory.getNativeClient();
            assertNotNull(client, "the client is made at start-up, the connection on first use");
            BeanPostProcessor processor = PlatformAutoConfiguration.RedisConfiguration.analyticsRedisListener(
                    new DefaultListableBeanFactory().getBeanProvider(Platform.class), SpringSupportTest.env(new HashMap<>()));
            processor.postProcessAfterInitialization(factory, "redisConnectionFactory");
            assertEquals(1, listeners(client).size());

            HashMap<String, Object> off = new HashMap<>();
            off.put("analytics.queries.enabled", "false");
            PlatformAutoConfiguration.RedisConfiguration.analyticsRedisListener(
                    new DefaultListableBeanFactory().getBeanProvider(Platform.class), SpringSupportTest.env(off))
                    .postProcessAfterInitialization(factory, "redisConnectionFactory");
            assertEquals(1, listeners(client).size(), "analytics.queries.enabled=false adds nothing");
        } finally {
            factory.destroy();
        }
    }
}
